#![forbid(unsafe_code)]
//! Integration tests for `bamabi_native_rt::net` and POD `Messages<M>` bridge registration
//! across both `shared-bridge` and `static-console` profiles.

use bamabi_native_rt::{
    FLAG_IS_HANDSHAKE, FLAG_IS_RELIABLE, PACKET_KIND_COMPONENT_DELTA, PACKET_KIND_HANDSHAKE,
    STRATA_NET_MAX_PAYLOAD_BYTES, STRATA_NET_PACKET_CANONICAL_NAME, STRATA_NET_PACKET_MAGIC,
    STRATA_NET_WIRE_VERSION, SharedBridgeAppExt, StrataBridgeCatalog, StrataNetPacket,
    dequantize_scalar_f64, pack_bits_le, quantize_scalar_f64, unpack_bits_le,
    verify_handshake_fingerprint,
};
use bamabi_sys::{
    AbiPod, BamFieldKind, ComponentUuid, ModComponent, fnv1a_64_init, fnv1a_64_update_bytes,
    fnv1a_64_update_u64,
};
use bevy_app::{App, Update};
use bevy_ecs::message::{Message, MessageReader, MessageWriter};
use bevy_ecs::prelude::Resource;

#[repr(C)]
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq, Message, bamabi_macros::ModComponent)]
#[mod_component(name = "net_rt_test::CustomPodMsg")]
struct CustomPodMsg {
    seq: u32,
    val: u32,
}

#[test]
fn stratanet_packet_layout_and_identity_match_wire_spec() {
    assert_eq!(core::mem::size_of::<StrataNetPacket>(), 184);
    assert_eq!(core::mem::align_of::<StrataNetPacket>(), 8);
    assert_eq!(
        <StrataNetPacket as ModComponent>::CANONICAL_NAME,
        STRATA_NET_PACKET_CANONICAL_NAME
    );
    assert_eq!(
        <StrataNetPacket as ModComponent>::CANONICAL_NAME,
        "strata::net::StrataNetPacket"
    );
    const {
        assert!(<StrataNetPacket as ModComponent>::IS_ABI_POD);
    }
    bamabi_sys::assert_abi_pod::<StrataNetPacket>();

    // Sum of all BAM_FIELDS sizes must equal 184 (zero implicit padding).
    let fields = <StrataNetPacket as ModComponent>::BAM_FIELDS;
    let total_field_bytes: usize = fields.iter().map(|f| f.size).sum();
    assert_eq!(total_field_bytes, 184);

    // Recompute wire identity independently from bamabi_sys primitives and confirm bit-for-bit
    // parity with #[derive(ModComponent)] (and strata_codegen::net).
    let expected_fields: &[(&str, BamFieldKind, &str, usize, usize, usize)] = &[
        ("module_net_fingerprint", BamFieldKind::U64, "u64", 0, 8, 8),
        ("item_schema_fingerprint", BamFieldKind::U64, "u64", 8, 8, 8),
        ("target_id", BamFieldKind::U64, "u64", 16, 8, 8),
        ("entity_bits", BamFieldKind::U64, "u64", 24, 8, 8),
        ("magic", BamFieldKind::U32, "u32", 32, 4, 4),
        ("tick_or_seq", BamFieldKind::U32, "u32", 36, 4, 4),
        ("version", BamFieldKind::U16, "u16", 40, 2, 2),
        ("payload_bits", BamFieldKind::U16, "u16", 42, 2, 2),
        ("flags", BamFieldKind::U16, "u16", 44, 2, 2),
        ("kind", BamFieldKind::U8, "u8", 46, 1, 1),
        ("channel", BamFieldKind::U8, "u8", 47, 1, 1),
        ("payload_bytes", BamFieldKind::U8, "u8", 48, 1, 1),
        ("client_id", BamFieldKind::U8, "u8", 49, 1, 1),
        ("_pad", BamFieldKind::NESTED, "[u8;6]", 50, 6, 1),
        ("payload", BamFieldKind::NESTED, "[u8;128]", 56, 128, 1),
    ];

    let mut schema_hash = 0u64;
    let mut fp = fnv1a_64_init();
    fp = fnv1a_64_update_bytes(fp, STRATA_NET_PACKET_CANONICAL_NAME.as_bytes());
    fp = fnv1a_64_update_u64(fp, 184);
    fp = fnv1a_64_update_u64(fp, 8);
    fp = fnv1a_64_update_u64(fp, 0);
    for (idx, &(name, kind, tag, off, sz, al)) in expected_fields.iter().enumerate() {
        assert_eq!(fields[idx].kind, kind);
        assert_eq!(fields[idx].name.len, name.len());
        assert_eq!(fields[idx].type_tag.len, tag.len());
        assert_eq!(fields[idx].offset, off);
        assert_eq!(fields[idx].size, sz);
        assert_eq!(fields[idx].align, al);
        schema_hash = ComponentUuid::hash_field_schema(schema_hash, name, tag, off);
        fp = fnv1a_64_update_u64(fp, u64::from(kind.0));
        fp = fnv1a_64_update_bytes(fp, name.as_bytes());
        fp = fnv1a_64_update_bytes(fp, tag.as_bytes());
        fp = fnv1a_64_update_u64(fp, off as u64);
        fp = fnv1a_64_update_u64(fp, sz as u64);
        fp = fnv1a_64_update_u64(fp, al as u64);
    }
    let expected_uuid =
        ComponentUuid::from_parts(STRATA_NET_PACKET_CANONICAL_NAME, 184, 8, schema_hash);

    assert_eq!(<StrataNetPacket as ModComponent>::UUID, expected_uuid);
    assert_eq!(<StrataNetPacket as ModComponent>::SCHEMA_FINGERPRINT, fp);
    assert_eq!(
        <StrataNetPacket as ModComponent>::SCHEMA_FINGERPRINT,
        0x7835_BC96_B507_EFCE
    );
    assert_ne!(fp, 0);
}

#[derive(Resource, Default)]
struct ReceivedPackets(Vec<StrataNetPacket>);

#[test]
fn register_strata_pod_stream_and_net_transport_work_across_profiles() {
    let mut app = App::new();
    let net_handle = app
        .register_strata_net_transport()
        .expect("register StrataNetPacket transport");
    let custom_handle = app
        .register_strata_pod_stream::<CustomPodMsg>()
        .expect("register custom POD stream");

    assert_eq!(net_handle.uuid, <StrataNetPacket as ModComponent>::UUID);
    assert_eq!(custom_handle.uuid, <CustomPodMsg as ModComponent>::UUID);

    let catalog = app.world().resource::<StrataBridgeCatalog>();
    let net_entry = catalog
        .get_by_uuid(&net_handle.uuid)
        .expect("catalog entry for StrataNetPacket");
    assert_eq!(net_entry.canonical_name, "strata::net::StrataNetPacket");
    assert_eq!(
        net_entry.schema_fingerprint,
        <StrataNetPacket as ModComponent>::SCHEMA_FINGERPRINT
    );

    #[cfg(feature = "shared-bridge")]
    {
        assert!(net_handle.abi_component_raw.is_some());
        assert!(custom_handle.abi_component_raw.is_some());
        let mod_reg = app.world().resource::<bamabi_host::ModRegistry>();
        let reg_pkt = mod_reg
            .get_by_uuid(&net_handle.uuid)
            .expect("ModRegistry resolves StrataNetPacket");
        assert!(reg_pkt.is_abi_pod);
        assert_ne!(
            reg_pkt.storage_flags & bamabi_sys::BAM_STORAGE_FLAG_MESSAGE,
            0
        );
        assert_eq!(reg_pkt.size, 184);
        assert_eq!(reg_pkt.align, 8);
        assert_eq!(
            reg_pkt.schema_fingerprint,
            <StrataNetPacket as ModComponent>::SCHEMA_FINGERPRINT
        );
        // POD Messages<M> enables Slots 30-32 (`msg_read_batch`, `msg_send`, `msg_write_batch`).
        assert!(reg_pkt.msg_read_batch_fn.is_some());
        assert!(reg_pkt.msg_send_fn.is_some());
        assert!(reg_pkt.msg_write_batch_fn.is_some());

        let reg_custom = mod_reg
            .get_by_uuid(&custom_handle.uuid)
            .expect("ModRegistry resolves CustomPodMsg");
        assert!(reg_custom.is_abi_pod);
        assert!(reg_custom.msg_write_batch_fn.is_some());
    }

    #[cfg(not(feature = "shared-bridge"))]
    {
        assert_eq!(net_handle.abi_component_raw, None);
        assert_eq!(custom_handle.abi_component_raw, None);
    }

    // Verify Messages<StrataNetPacket> read/write works inside Bevy Update in both profiles.
    app.insert_resource(ReceivedPackets::default());
    fn send_handshake(mut writer: MessageWriter<StrataNetPacket>) {
        writer.write(StrataNetPacket::new_handshake(0x1234_5678_9ABC_DEF0, 2, 7));
    }
    fn recv_packets(
        mut reader: MessageReader<StrataNetPacket>,
        mut out: bevy_ecs::prelude::ResMut<ReceivedPackets>,
    ) {
        out.0.extend(reader.read().copied());
    }
    app.add_systems(
        Update,
        bevy_ecs::schedule::IntoScheduleConfigs::chain((send_handshake, recv_packets)),
    );
    app.update();

    let rx = &app.world().resource::<ReceivedPackets>().0;
    assert_eq!(rx.len(), 1);
    assert!(rx[0].verify_handshake(0x1234_5678_9ABC_DEF0));
    assert!(!rx[0].verify_handshake(0x1234_5678_9ABC_DEF1));
}

#[test]
fn quantization_bit_packing_and_handshake_rejection() {
    // 1-bit, 12-bit, 16-bit, 32-bit round-trips.
    let q1 = quantize_scalar_f64(10.0, 0.0, 10.0, 1, None);
    assert_eq!(q1, 1);
    assert_eq!(dequantize_scalar_f64(q1, 0.0, 10.0, 1, None), 10.0);

    let q12 = quantize_scalar_f64(-24.5, -100.0, 100.0, 12, None);
    let q16 = quantize_scalar_f64(13.75, -50.0, 50.0, 16, Some(0.005));
    let q32 = quantize_scalar_f64(543_210.25, -1_000_000.0, 1_000_000.0, 32, None);

    let mut pkt = StrataNetPacket {
        module_net_fingerprint: 0xDEAD_BEEF_CAFE_0001,
        item_schema_fingerprint: 0xDEAD_BEEF_CAFE_0002,
        target_id: 42,
        entity_bits: 0x0001_0000_0007,
        magic: STRATA_NET_PACKET_MAGIC,
        tick_or_seq: 99,
        version: STRATA_NET_WIRE_VERSION,
        payload_bits: 1 + 12 + 16 + 32,
        flags: FLAG_IS_RELIABLE,
        kind: PACKET_KIND_COMPONENT_DELTA,
        channel: 1,
        payload_bytes: 8,
        client_id: 0,
        _pad: [0; 6],
        payload: [0; STRATA_NET_MAX_PAYLOAD_BYTES],
    };

    pack_bits_le(&mut pkt.payload, 0, 1, q1);
    pack_bits_le(&mut pkt.payload, 1, 12, q12);
    pack_bits_le(&mut pkt.payload, 13, 16, q16);
    pack_bits_le(&mut pkt.payload, 29, 32, q32);

    assert_eq!(unpack_bits_le(&pkt.payload, 0, 1), q1);
    assert_eq!(unpack_bits_le(&pkt.payload, 1, 12), q12);
    assert_eq!(unpack_bits_le(&pkt.payload, 13, 16), q16);
    assert_eq!(unpack_bits_le(&pkt.payload, 29, 32), q32);

    let d12 = dequantize_scalar_f64(unpack_bits_le(&pkt.payload, 1, 12), -100.0, 100.0, 12, None);
    let d16 = dequantize_scalar_f64(
        unpack_bits_le(&pkt.payload, 13, 16),
        -50.0,
        50.0,
        16,
        Some(0.005),
    );
    let d32 = dequantize_scalar_f64(
        unpack_bits_le(&pkt.payload, 29, 32),
        -1_000_000.0,
        1_000_000.0,
        32,
        None,
    );
    assert!((d12 - (-24.5)).abs() < 0.05, "d12={d12}");
    assert!((d16 - 13.75).abs() <= 0.005, "d16={d16}");
    assert!((d32 - 543_210.25).abs() < 1e-3, "d32={d32}");

    // Valid frame vs corrupted fingerprint / magic / version / length checks.
    assert!(pkt.verify_item_frame(0xDEAD_BEEF_CAFE_0001, 0xDEAD_BEEF_CAFE_0002));
    assert!(!pkt.verify_item_frame(0xDEAD_BEEF_CAFE_0099, 0xDEAD_BEEF_CAFE_0002));
    assert!(!pkt.verify_item_frame(0xDEAD_BEEF_CAFE_0001, 0xDEAD_BEEF_CAFE_0099));
    assert!(!verify_handshake_fingerprint(0, 0));

    let mut bad_len = pkt;
    bad_len.payload_bytes = (STRATA_NET_MAX_PAYLOAD_BYTES as u8) + 1;
    assert!(!bad_len.verify_item_frame(0xDEAD_BEEF_CAFE_0001, 0xDEAD_BEEF_CAFE_0002));

    let hs = StrataNetPacket::new_handshake(0x1122_3344_5566_7788, 3, 10);
    assert_eq!(hs.kind, PACKET_KIND_HANDSHAKE);
    assert_ne!(hs.flags & FLAG_IS_HANDSHAKE, 0);
    assert_ne!(hs.flags & FLAG_IS_RELIABLE, 0);
    assert!(hs.verify_handshake(0x1122_3344_5566_7788));
    assert!(!hs.verify_handshake(0x1122_3344_5566_7789));
}

#[test]
fn assert_abi_pod_bound_compile_check() {
    fn require_pod<T: AbiPod>() {}
    require_pod::<StrataNetPacket>();
    require_pod::<CustomPodMsg>();
}
