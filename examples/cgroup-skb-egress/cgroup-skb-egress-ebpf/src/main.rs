#![no_std]
#![no_main]
#![forbid(unsafe_code)]

use aya_ebpf::cgroup_skb_egress_bindings::iphdr;

use aya_ebpf::{
    black_box,
    macros::{cgroup_skb, map},
    maps::{HashMap, PerfEventArray, EbpfAtomicI64},
    programs::SkBuffContext,
};
use memoffset::offset_of;

use cgroup_skb_egress_common::PacketLog;

// BUG: The use of core should be disable because ManuallyDrop (and likely other
// parts) conflict with guarantee-non-static-destructors.
use core::mem::ManuallyDrop;

#[map]
static EVENTS: PerfEventArray<PacketLog> = PerfEventArray::new(0);

// TODO: make this work with unpriv. eBPF (perm. denied creating map)
#[map] // (1)
static BLOCKLIST: HashMap<u32, EbpfAtomicI64> = HashMap::with_max_entries(1024, 0);

#[cgroup_skb]
pub fn cgroup_skb_egress(ctx: SkBuffContext) -> i32 {
    match { try_cgroup_skb_egress(ctx) } {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

// (2)
fn block_ip(address: u32) -> bool {
    BLOCKLIST.atomic_get_i64(&address).is_some()
}

/// Converts lifetime `'b` to lifetime `'a`.
///
/// This function, on its own, is sound:
/// - `_val_a`'s lifetime is `&'a &'b`. This means that `'b` must outlive `'a`, so
/// that the `'a` reference is never dangling. If `'a` outlived `'b` then it could
/// borrow data that's already been dropped.
/// - Therefore, `val_b`, which has a lifetime of `'b`, is valid for `'a`.
#[inline(never)]
pub const fn lifetime_translator<'a, 'b, T: ?Sized>(_val_a: &'a &'b (), val_b: &'b T) -> &'a T {
	val_b
}

/// This does the same thing as [`lifetime_translator`], just for mutable refs.
#[inline(never)]
pub fn lifetime_translator_mut<'a, 'b, T: ?Sized>(
	_val_a: &'a &'b (),
	val_b: &'b mut T,
) -> &'a mut T {
	val_b
}

/// Expands the domain of `'a` to `'b`.
///
/// # Safety
///
/// Safety? What's that?
pub fn expand<'a, 'b, T: ?Sized>(x: &'a T) -> &'b T {
	let f: for<'x> fn(_, &'x T) -> &'b T = lifetime_translator;
	f(STATIC_UNIT, x)
}

/// This does the same thing as [`expand`] for mutable references.
///
/// # Safety
///
/// Safety? What's that?
pub fn expand_mut<'a, 'b, T: ?Sized>(x: &'a mut T) -> &'b mut T {
	let f: for<'x> fn(_, &'x mut T) -> &'b mut T = lifetime_translator_mut;
	f(STATIC_UNIT, x)
}

/// A unit with a static lifetime.
///
/// Thanks to the soundness hole, this lets us cast any value all the way up to
/// a `'static` lifetime, meaning any lifetime we want.
pub const STATIC_UNIT: &&() = &&();

// Workaround: https://github.com/Speykious/cve-rs/blob/main/src/transmute.rs#L38 does not work because aya does not offer a Box.
#[allow(unused_assignments)]
pub fn transmute<A: Copy, B: Copy>(obj: A) -> B {
	// The layout of `DummyEnum` is approximately
	// DummyEnum {
	//     is_a_or_b: u8,
	//     data: usize,
	// }
	// Note that `data` is shared between `DummyEnum::A` and `DummyEnum::B`.
	// This should hopefully be more reliable than spamming the stack with a value and hoping the memory
	// is placed correctly by the compiler.
	enum DummyEnum<A, B> {
		A(Result<A, Option<Blank<A, B>>>),
		B(Result<B, Option<Blank<A, B>>>),
	}

	union Blank<A, B> {
		_a: ManuallyDrop<A>,
		_b: ManuallyDrop<B>,
	}

	let mut res = DummyEnum::B(Err(None));
	let DummyEnum::B(ref_to_b) = &mut res else {
		unreachable!()
	};
	let ref_to_b = expand_mut(ref_to_b);
	res = DummyEnum::A(Ok(obj));
	core::mem::replace(ref_to_b, Err(None)).ok().unwrap()
}

fn try_cgroup_skb_egress(ctx: SkBuffContext) -> Result<i32, i64> {

    // Leak ctx location
    //
    // Rejected by eBPF verifier (fc41) if num is 32-bit: invalid size of register spill
    // Accepted by priv. eBPF verifier, leaks pointer to map.
    let num = transmute(ctx);
    //
    // Rejected by Rust compiler:
    // let num = ctx;
    //
    // Works:
    // let num = 64;
    let log_entry = PacketLog {
        ipv4_address: 0,
        action: num,
    };
    EVENTS.output(&ctx, &log_entry, 0);

    let protocol = ctx.skb.protocol();
    if protocol != ETH_P_IP {
        return Ok(1);
    }

    let destination = u32::from_be(ctx.load(offset_of!(iphdr, daddr))?);

    // (3)
    let action = if block_ip(destination) { 0 } else { 1 };

    let log_entry = PacketLog {
        ipv4_address: destination,
        action: action,
    };
    EVENTS.output(&ctx, &log_entry, 0);

    Ok(action as i32)
}

const ETH_P_IP: u32 = 8;

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unreachable!()
}
