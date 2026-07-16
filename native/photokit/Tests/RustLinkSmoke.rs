use std::ffi::c_void;
use std::slice;
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

#[repr(C)]
struct Frame {
    abi_version: u32,
    kind: u32,
    sequence: u64,
    length: usize,
}

#[repr(C)]
struct PersonDetectionRequest {
    abi_version: u32,
    struct_size: u32,
    width: u32,
    height: u32,
    bytes_per_row: u64,
    rgb_length: u64,
    reserved_0: u32,
    reserved_1: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct PersonRect {
    abi_version: u32,
    struct_size: u32,
    left: u32,
    top: u32,
    width: u32,
    height: u32,
    confidence_basis_points: u32,
    result_ordinal: u32,
    reserved_0: u32,
}

#[repr(C)]
struct PersonDetectionMetadata {
    abi_version: u32,
    struct_size: u32,
    request_revision: u32,
    result_count: u32,
    os_major: u32,
    os_minor: u32,
    os_patch: u32,
    reserved_0: u32,
    os_build: [u8; 32],
    vision_framework_build: [u8; 32],
}

extern "C" {
    fn wk_photokit_create_v1(requested_abi: u32, out: *mut *mut c_void) -> i32;
    fn wk_photokit_send_v1(handle: *mut c_void, bytes: *const u8, length: usize) -> i32;
    fn wk_photokit_next_v1(handle: *mut c_void, timeout_ms: u32, out: *mut *mut Frame) -> i32;
    fn wk_photokit_frame_free_v1(frame: *mut Frame);
    fn wk_photokit_quiesce_v1(handle: *mut c_void, timeout_ms: u32) -> i32;
    fn wk_photokit_destroy_v1(handle: *mut *mut c_void) -> i32;
    fn wk_detect_people_rgb_v1(
        request: *const PersonDetectionRequest,
        rgb: *const u8,
        out_rects: *mut PersonRect,
        output_capacity: u32,
        out_count: *mut u32,
        out_metadata: *mut PersonDetectionMetadata,
    ) -> i32;

    static kCFRunLoopDefaultMode: *const c_void;
    fn CFRunLoopRunInMode(
        mode: *const c_void,
        seconds: f64,
        return_after_source_handled: u8,
    ) -> i32;
}

fn main() {
    let (result_tx, result_rx) = mpsc::sync_channel(1);
    let worker = thread::spawn(move || {
        let result = run_smoke();
        let _ = result_tx.send(result);
    });

    let deadline = Instant::now() + Duration::from_secs(10);
    let result = loop {
        match result_rx.try_recv() {
            Ok(result) => break result,
            Err(mpsc::TryRecvError::Disconnected) => break Err("worker disconnected".to_owned()),
            Err(mpsc::TryRecvError::Empty) => {}
        }
        assert!(Instant::now() < deadline, "real C ABI smoke timed out");
        unsafe {
            CFRunLoopRunInMode(kCFRunLoopDefaultMode, 0.05, 1);
        }
    };
    worker.join().expect("worker panicked");
    result.expect("real C ABI smoke failed");
}

fn run_smoke() -> Result<(), String> {
    run_person_detection_smoke()?;

    let mut handle = std::ptr::null_mut();
    status(unsafe { wk_photokit_create_v1(1, &mut handle) }, "create")?;
    if handle.is_null() {
        return Err("create returned a null handle".to_owned());
    }

    let command = br#"{"protocol_version":1,"command":"inspect_authorization","operation_id":"11111111-1111-4111-8111-111111111111","enrollment_epoch":"22222222-2222-4222-8222-222222222222","reconciliation_fence":7,"generation":9,"sequence":11}"#;
    status(
        unsafe { wk_photokit_send_v1(handle, command.as_ptr(), command.len()) },
        "send",
    )?;

    let mut expected_frame_sequence = 1_u64;
    let mut saw_authorization = false;
    let mut saw_terminal = false;
    while !saw_terminal {
        let mut frame = std::ptr::null_mut();
        let next_status = unsafe { wk_photokit_next_v1(handle, 1_000, &mut frame) };
        if next_status == 1 {
            if !frame.is_null() {
                return Err("timeout returned a frame".to_owned());
            }
            continue;
        }
        status(next_status, "next")?;
        if frame.is_null() {
            return Err("OK returned a null frame".to_owned());
        }
        let checked = validate_frame(frame, expected_frame_sequence);
        unsafe { wk_photokit_frame_free_v1(frame) };
        let control = checked?;
        expected_frame_sequence += 1;
        if control.contains("\"event\":\"authorization\"") {
            saw_authorization = true;
        } else if control.contains("\"event\":\"operation_terminal\"")
            && control.contains("\"status\":\"completed\"")
        {
            saw_terminal = true;
        } else {
            return Err("unexpected control event".to_owned());
        }
    }
    if !saw_authorization {
        return Err("authorization event was not emitted".to_owned());
    }

    status(unsafe { wk_photokit_quiesce_v1(handle, 1_000) }, "quiesce")?;
    status(unsafe { wk_photokit_destroy_v1(&mut handle) }, "destroy")?;
    if !handle.is_null() {
        return Err("destroy did not null the handle".to_owned());
    }
    Ok(())
}

fn run_person_detection_smoke() -> Result<(), String> {
    if std::mem::size_of::<PersonDetectionRequest>() != 40
        || std::mem::size_of::<PersonRect>() != 36
        || std::mem::size_of::<PersonDetectionMetadata>() != 96
    {
        return Err("person detection ABI layout drifted".to_owned());
    }
    let side = 256_usize;
    let mut rgb = vec![0_u8; side * side * 3];
    for pixel in 0..(side * side) {
        let value = if ((pixel / side) / 16 + (pixel % side) / 16) % 2 == 0 {
            48
        } else {
            208
        };
        rgb[pixel * 3] = value;
        rgb[pixel * 3 + 1] = value;
        rgb[pixel * 3 + 2] = value;
    }
    let request = PersonDetectionRequest {
        abi_version: 1,
        struct_size: 40,
        width: side as u32,
        height: side as u32,
        bytes_per_row: (side * 3) as u64,
        rgb_length: rgb.len() as u64,
        reserved_0: 0,
        reserved_1: 0,
    };
    let empty = PersonRect {
        abi_version: 0,
        struct_size: 0,
        left: 0,
        top: 0,
        width: 0,
        height: 0,
        confidence_basis_points: 0,
        result_ordinal: 0,
        reserved_0: 0,
    };
    let mut rectangles = [empty; 32];
    let mut count = 99_u32;
    let mut metadata = PersonDetectionMetadata {
        abi_version: 0,
        struct_size: 0,
        request_revision: 0,
        result_count: 0,
        os_major: 0,
        os_minor: 0,
        os_patch: 0,
        reserved_0: 0,
        os_build: [0; 32],
        vision_framework_build: [0; 32],
    };
    status(
        unsafe {
            wk_detect_people_rgb_v1(
                &request,
                rgb.as_ptr(),
                rectangles.as_mut_ptr(),
                rectangles.len() as u32,
                &mut count,
                &mut metadata,
            )
        },
        "detect people",
    )?;
    if count != 0
        || metadata.abi_version != 1
        || metadata.struct_size != 96
        || metadata.request_revision != 2
        || metadata.os_build[0] == 0
        || metadata.vision_framework_build[0] == 0
    {
        return Err("person detection metadata was invalid".to_owned());
    }
    Ok(())
}

fn validate_frame(frame: *const Frame, expected_sequence: u64) -> Result<String, String> {
    let header = unsafe { &*frame };
    if std::mem::size_of::<Frame>() != 24
        || header.abi_version != 1
        || header.kind != 1
        || header.sequence != expected_sequence
        || header.length == 0
        || header.length > 65_536
    {
        return Err("invalid frame header".to_owned());
    }
    let bytes = unsafe {
        slice::from_raw_parts(
            (frame as *const u8).add(std::mem::size_of::<Frame>()),
            header.length,
        )
    };
    let control = std::str::from_utf8(bytes)
        .map_err(|_| "control frame was not UTF-8")?
        .to_owned();
    for expected in [
        "\"protocol_version\":1",
        "\"operation_id\":\"11111111-1111-4111-8111-111111111111\"",
        "\"enrollment_epoch\":\"22222222-2222-4222-8222-222222222222\"",
        "\"reconciliation_fence\":7",
        "\"generation\":9",
        "\"sequence\":11",
    ] {
        if !control.contains(expected) {
            return Err(format!("control identity missing {expected}"));
        }
    }
    Ok(control)
}

fn status(actual: i32, operation: &str) -> Result<(), String> {
    if actual == 0 {
        Ok(())
    } else {
        Err(format!("{operation} returned status {actual}"))
    }
}
