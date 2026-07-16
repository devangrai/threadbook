import AppKit
import Photos
import PhotosUI
import P00PhotoKitCore

private struct PreparedResource {
    let resource: PHAssetResource
    let dimensions: ImageDimensions
    let assetAlias: String
    let resourceAlias: String
}

final class ProbeViewController: NSViewController, PHPickerViewControllerDelegate {
    private let challenge: LiveChallenge
    private let evidenceContext: LiveEvidenceContext
    private let emitter: LiveRecordEmitter
    private let aliases: AliasFactory
    private let outputStore: PrivateRunOutputStore
    private var preparedResources: [PreparedResource] = []
    private var nextResourceIndex = 0
    private var completedEvidence: [FixtureRole: CompletedResourceEvidence] = [:]
    private var activeOperation: PhotoResourceOperation?

    private let statusLabel = NSTextField(labelWithString: "Ready")
    private let chooseButton = NSButton(title: "Choose Photos", target: nil, action: nil)
    private let cancelButton = NSButton(title: "Cancel", target: nil, action: nil)

    init(
        challenge: LiveChallenge,
        evidenceContext: LiveEvidenceContext,
        emitter: LiveRecordEmitter,
        aliases: AliasFactory,
        outputStore: PrivateRunOutputStore
    ) {
        self.challenge = challenge
        self.evidenceContext = evidenceContext
        self.emitter = emitter
        self.aliases = aliases
        self.outputStore = outputStore
        super.init(nibName: nil, bundle: nil)
    }

    @available(*, unavailable)
    required init?(coder: NSCoder) {
        fatalError("init(coder:) is unavailable")
    }

    override func loadView() {
        let container = NSView()
        container.translatesAutoresizingMaskIntoConstraints = false

        let title = NSTextField(labelWithString: "PhotoKit Native Probe")
        title.font = .systemFont(ofSize: 22, weight: .semibold)
        statusLabel.font = .systemFont(ofSize: 13)
        statusLabel.textColor = .secondaryLabelColor

        chooseButton.target = self
        chooseButton.action = #selector(choosePhotos)
        chooseButton.bezelStyle = .rounded
        chooseButton.keyEquivalent = "\r"

        cancelButton.target = self
        cancelButton.action = #selector(cancelProbe)
        cancelButton.bezelStyle = .rounded
        cancelButton.isEnabled = false

        let buttons = NSStackView(views: [chooseButton, cancelButton])
        buttons.orientation = .horizontal
        buttons.spacing = 8

        let stack = NSStackView(views: [title, statusLabel, buttons])
        stack.orientation = .vertical
        stack.alignment = .leading
        stack.spacing = 14
        stack.translatesAutoresizingMaskIntoConstraints = false
        container.addSubview(stack)

        NSLayoutConstraint.activate([
            stack.leadingAnchor.constraint(equalTo: container.leadingAnchor, constant: 28),
            stack.trailingAnchor.constraint(lessThanOrEqualTo: container.trailingAnchor, constant: -28),
            stack.topAnchor.constraint(equalTo: container.topAnchor, constant: 28),
            stack.bottomAnchor.constraint(lessThanOrEqualTo: container.bottomAnchor, constant: -28),
            buttons.heightAnchor.constraint(equalToConstant: 32),
        ])
        view = container
    }

    @objc private func choosePhotos() {
        chooseButton.isEnabled = false
        statusLabel.stringValue = "Checking Photos access"
        PHPhotoLibrary.requestAuthorization(for: .readWrite) { [weak self] status in
            DispatchQueue.main.async {
                self?.handleAuthorization(status)
            }
        }
    }

    private func handleAuthorization(_ status: PHAuthorizationStatus) {
        guard status == .authorized else {
            blockSession()
            return
        }
        do {
            try emitter.emit(.authorizationGranted)
        } catch {
            blockSession()
            return
        }
        var configuration = PHPickerConfiguration(photoLibrary: .shared())
        configuration.filter = .images
        configuration.selectionLimit = 2
        configuration.preferredAssetRepresentationMode = .current
        let picker = PHPickerViewController(configuration: configuration)
        picker.delegate = self
        statusLabel.stringValue = "Waiting for selection"
        presentAsSheet(picker)
    }

    func picker(_ picker: PHPickerViewController, didFinishPicking results: [PHPickerResult]) {
        dismiss(picker)
        guard results.count == 2 else {
            blockSession()
            return
        }
        do {
            preparedResources = try prepare(results)
        } catch {
            blockSession()
            return
        }
        guard Set(preparedResources.map(\.assetAlias)).count == 2,
              Set(preparedResources.map(\.resourceAlias)).count == 2 else {
            blockSession()
            return
        }
        do {
            for prepared in preparedResources {
                try emitter.emit(
                    .resourceSelected(
                        assetAlias: prepared.assetAlias,
                        resourceAlias: prepared.resourceAlias
                    )
                )
            }
        } catch {
            blockSession()
            return
        }

        cancelButton.isEnabled = true
        statusLabel.stringValue = "Running native probes"
        nextResourceIndex = 0
        completedEvidence = [:]
        startNextResource()
    }

    private func prepare(_ results: [PHPickerResult]) throws -> [PreparedResource] {
        var seenIdentifiers = Set<String>()
        return try results.map { result in
            guard let identifier = result.assetIdentifier,
                  seenIdentifiers.insert(identifier).inserted else {
                throw ResourceRejection.ambiguousResourceSet
            }

            let fetch = PHAsset.fetchAssets(
                withLocalIdentifiers: [identifier],
                options: nil
            )
            guard fetch.count == 1,
                  let asset = fetch.firstObject,
                  asset.localIdentifier == identifier,
                  asset.pixelWidth > 0,
                  asset.pixelHeight > 0 else {
                throw ResourceRejection.ambiguousResourceSet
            }

            let assetAlias = aliases.assetAlias(localIdentifier: identifier)
            let resources = PHAssetResource.assetResources(for: asset)
            let candidates = resources.enumerated().map { index, resource in
                ResourceCandidate(
                    token: String(index),
                    kind: mapResourceKind(resource.type),
                    uniformTypeIdentifier: resource.uniformTypeIdentifier
                )
            }
            let selected = try OriginalPrimaryResourcePolicy.select(
                assetKind: mapAssetKind(asset.mediaType),
                isLivePhoto: asset.mediaSubtypes.contains(.photoLive),
                candidates: candidates
            ).get()
            guard let selectedIndex = Int(selected.token),
                  resources.indices.contains(selectedIndex) else {
                throw ResourceRejection.unsupportedResource
            }

            let resourceBinding = [
                identifier,
                OriginalPrimaryResourcePolicy.identifier,
                selected.uniformTypeIdentifier,
                selected.token,
            ].joined(separator: ":")
            let resourceAlias = aliases.resourceAlias(binding: resourceBinding)
            return PreparedResource(
                resource: resources[selectedIndex],
                dimensions: ImageDimensions(
                    width: asset.pixelWidth,
                    height: asset.pixelHeight
                ),
                assetAlias: assetAlias,
                resourceAlias: resourceAlias
            )
        }
    }

    private func startNextResource() {
        guard nextResourceIndex < preparedResources.count else {
            finishSession()
            return
        }
        let prepared = preparedResources[nextResourceIndex]
        nextResourceIndex += 1
        let operation = PhotoResourceOperation(
            resource: prepared.resource,
            challenge: challenge,
            selectedDimensions: prepared.dimensions,
            assetAlias: prepared.assetAlias,
            resourceAlias: prepared.resourceAlias,
            outputStore: outputStore,
            evidenceContext: evidenceContext,
            emitter: emitter
        ) { [weak self] result in
            self?.operationFinished(result)
        }
        activeOperation = operation
        operation.start()
    }

    private func operationFinished(
        _ result: Result<CompletedResourceEvidence, TransferFailure>
    ) {
        activeOperation = nil
        switch result {
        case let .success(evidence):
            guard completedEvidence[evidence.role] == nil else {
                blockSession()
                return
            }
            completedEvidence[evidence.role] = evidence
            startNextResource()
        case .failure:
            blockSession()
        }
    }

    private func finishSession() {
        guard let local = completedEvidence[.local],
              let cloud = completedEvidence[.cloud],
              local.assetAlias != cloud.assetAlias,
              local.resourceAlias != cloud.resourceAlias else {
            blockSession()
            return
        }
        do {
            try emitter.emit(.sessionCompleted)
        } catch {
            blockSession()
            return
        }
        cancelButton.isEnabled = false
        statusLabel.stringValue = "Complete"
        terminate(after: 0.2, status: EXIT_SUCCESS)
    }

    @objc private func cancelProbe() {
        activeOperation?.cancel()
    }

    private func blockSession() {
        chooseButton.isEnabled = false
        cancelButton.isEnabled = false
        statusLabel.stringValue = "Blocked"
        terminate(after: 0.3, status: EX_SOFTWARE)
    }

    private func terminate(after delay: TimeInterval, status: Int32) {
        DispatchQueue.main.asyncAfter(deadline: .now() + delay) {
            fflush(stdout)
            fflush(stderr)
            exit(status)
        }
    }

    private func mapAssetKind(_ mediaType: PHAssetMediaType) -> AssetKind {
        switch mediaType {
        case .image: return .image
        case .video: return .video
        case .audio: return .audio
        case .unknown: return .unknown
        @unknown default: return .unknown
        }
    }

    private func mapResourceKind(_ type: PHAssetResourceType) -> ResourceKind {
        switch type {
        case .photo: return .originalPhoto
        case .fullSizePhoto, .adjustmentBasePhoto, .photoProxy: return .adjustedPhoto
        case .pairedVideo, .fullSizePairedVideo, .adjustmentBasePairedVideo:
            return .pairedVideo
        case .video, .fullSizeVideo, .adjustmentBaseVideo: return .video
        case .audio: return .audio
        case .adjustmentData: return .adjustmentData
        case .alternatePhoto: return .alternatePhoto
        @unknown default: return .unknown
        }
    }
}
