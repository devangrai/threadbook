use std::io::Cursor;

use image::{DynamicImage, ImageFormat, Rgb, RgbImage};
use wardrobe_core::{
    CatalogPort, CreateManualOutfitV1Request, DeletionTargetKindV1, GetOutfitCollageV1Request,
    ImportLocalSourcesV1Request, InboxStateV1, ItemAttributesV1, ItemCategoryV1,
    ListInboxV1Request, ListOutfitsV1Request, OutfitAssetStateV1, OutfitPort,
    PreviewDeletionV1Request, ReplayStatusV1, RequestId, SaveItemV1Request, SCHEMA_VERSION_V1,
};
use wardrobe_platform::{Database, PrivateAppPaths};

fn request_id() -> RequestId {
    RequestId::new_v4()
}

fn attributes(name: &str, category: ItemCategoryV1, color: &str) -> ItemAttributesV1 {
    ItemAttributesV1 {
        display_name: name.to_owned(),
        category,
        subcategory: None,
        brand: None,
        primary_color: Some(color.to_owned()),
        size: None,
        notes: None,
        tags: Vec::new(),
    }
}

#[test]
fn real_import_save_restart_and_collage_preserve_pinned_assets() {
    let temporary = tempfile::tempdir().unwrap();
    let paths = PrivateAppPaths::create(temporary.path().join("app")).unwrap();
    let image_path = temporary.path().join("shirt.png");
    let mut png = Vec::new();
    DynamicImage::ImageRgb8(RgbImage::from_pixel(3, 2, Rgb([245, 245, 240])))
        .write_to(&mut Cursor::new(&mut png), ImageFormat::Png)
        .unwrap();
    std::fs::write(&image_path, &png).unwrap();

    let database = Database::open(&paths, 10).unwrap();
    database
        .import_local_sources(&ImportLocalSourcesV1Request {
            schema_version: SCHEMA_VERSION_V1,
            request_id: request_id(),
            paths: vec![image_path.to_string_lossy().into_owned()],
        })
        .unwrap();
    let inbox = database
        .list_inbox(&ListInboxV1Request {
            schema_version: SCHEMA_VERSION_V1,
            request_id: request_id(),
            state: InboxStateV1::Unresolved,
            cursor: None,
            limit: 10,
        })
        .unwrap();
    let evidence_id = inbox.evidence[0].evidence_id;
    let shirt = database
        .save_item_and_append_decision(&SaveItemV1Request {
            schema_version: SCHEMA_VERSION_V1,
            request_id: request_id(),
            item_id: None,
            attributes: attributes("Ivory Oxford Shirt", ItemCategoryV1::Top, "Ivory"),
            evidence_ids: vec![evidence_id],
            expected_catalog_revision: 0,
        })
        .unwrap()
        .item;
    let trousers = database
        .save_item_and_append_decision(&SaveItemV1Request {
            schema_version: SCHEMA_VERSION_V1,
            request_id: request_id(),
            item_id: None,
            attributes: attributes("Navy Trousers", ItemCategoryV1::Bottom, "Navy"),
            evidence_ids: Vec::new(),
            expected_catalog_revision: 1,
        })
        .unwrap()
        .item;

    let create_request = CreateManualOutfitV1Request {
        schema_version: SCHEMA_VERSION_V1,
        request_id: request_id(),
        name: "Dinner date".to_owned(),
        item_ids: vec![shirt.item_id, trousers.item_id],
        expected_catalog_revision: 2,
        expected_outfit_revision: 0,
    };
    let created = database.create_manual_outfit(&create_request).unwrap();
    assert_eq!(ReplayStatusV1::Created, created.replay_status);
    assert_eq!(
        OutfitAssetStateV1::Available,
        created.outfit.members[0].asset.state
    );
    assert_eq!(
        OutfitAssetStateV1::MetadataOnly,
        created.outfit.members[1].asset.state
    );
    let pinned_hash = created.outfit.members[0]
        .asset
        .blob_sha256
        .as_ref()
        .unwrap()
        .as_str()
        .to_owned();
    let pinned_source_id = created.outfit.members[0].asset.source_id.unwrap();
    let deletion_preview = database
        .preview_deletion(&PreviewDeletionV1Request {
            schema_version: SCHEMA_VERSION_V1,
            request_id: request_id(),
            target_kind: DeletionTargetKindV1::Source,
            target_id: pinned_source_id.to_string(),
            limit: 20,
        })
        .unwrap();
    assert_eq!(deletion_preview.retained_shared_blob_count, 1);

    let replay = database.create_manual_outfit(&create_request).unwrap();
    assert_eq!(ReplayStatusV1::Replayed, replay.replay_status);
    let mut changed = create_request.clone();
    changed.name = "Changed envelope".to_owned();
    assert!(database.create_manual_outfit(&changed).is_err());

    database
        .save_item_and_append_decision(&SaveItemV1Request {
            schema_version: SCHEMA_VERSION_V1,
            request_id: request_id(),
            item_id: Some(shirt.item_id),
            attributes: shirt.attributes,
            evidence_ids: Vec::new(),
            expected_catalog_revision: 2,
        })
        .unwrap();
    drop(database);

    let reopened = Database::open(&paths, 20).unwrap();
    let page = reopened
        .list_outfits(&ListOutfitsV1Request {
            schema_version: SCHEMA_VERSION_V1,
            request_id: request_id(),
            cursor: None,
            limit: 10,
        })
        .unwrap();
    assert_eq!(1, page.total_count);
    assert_eq!(
        pinned_hash,
        page.outfits[0].members[0]
            .asset
            .blob_sha256
            .as_ref()
            .unwrap()
            .as_str()
    );

    let collage = reopened
        .get_outfit_collage(&GetOutfitCollageV1Request {
            schema_version: SCHEMA_VERSION_V1,
            request_id: request_id(),
            outfit_id: created.outfit.outfit_id,
        })
        .unwrap();
    assert_eq!(png, collage.members[0].bytes.as_ref().unwrap().as_slice());
    assert!(collage.members[1].bytes.is_none());
    assert_eq!(
        "Ivory Oxford Shirt",
        collage.members[0].member.attributes.display_name
    );
    assert_eq!(
        "Navy Trousers",
        collage.members[1].member.attributes.display_name
    );
}
