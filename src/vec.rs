use std::{
    marker::PhantomData,
    mem::size_of,
    ptr,
    sync::atomic::{AtomicBool, AtomicI64, AtomicPtr, AtomicU64, AtomicUsize, Ordering},
};

use crossbeam::epoch::{self, pin, Atomic, Shared};

const BUCKET_CT: usize = 50;
const ATOMIC_I64_NULLPTR: AtomicPtr<AtomicI64> = AtomicPtr::new(ptr::null_mut());
const USIZE_SIZE_BITS: u32 = (size_of::<usize>() as u32) * 8;
const FIRST_BUCKET_SIZE: usize = 8;

// todo: cache pads
pub struct Vec<T> {
    buckets: Box<[AtomicPtr<AtomicI64>; BUCKET_CT]>,
    descriptor: Atomic<Descriptor<T>>,
}

struct Descriptor<T> {
    size: AtomicUsize,
    counter: AtomicUsize,
    pending: Atomic<WriteDescriptor<T>>,
}

struct WriteDescriptor<T> {
    cur: u64,
    next: u64,
    loc: AtomicU64,
    fin: AtomicBool,
    _phantom: PhantomData<T>,
}

trait HighestBit {
    fn highest_bit(&self) -> u32;
}

impl HighestBit for usize {
    fn highest_bit(&self) -> u32 {
        USIZE_SIZE_BITS - self.leading_zeros()
    }
}

#[test]
fn msb_test() {
    assert_eq!((120312 as usize).highest_bit(), 17);
}

/*
unsafe impl<T: Send> Send for Vec<T> {}
unsafe impl<T: Sync> Sync for Vec<T> {}
*/

// push_back
// pop_back
// reserve
// read
// write
// size

impl<T> Vec<T>
where
    T: Sized + Copy + Send + Sync,
{
    pub fn new() -> Self {
        Vec {
            buckets: Box::new([ATOMIC_I64_NULLPTR; BUCKET_CT]),
            descriptor: Atomic::new(Descriptor {
                size: AtomicUsize::new(0),
                counter: AtomicUsize::new(0),
                pending: Atomic::null(),
            }),
        }
    }

    pub fn read<'a>(&'a mut self, i: usize) -> &'a T {
        unsafe { self.at(i).as_ref() }.expect("must exist")
    }

    pub fn write(&mut self, i: usize, elem: T) {
        unsafe { *self.at(i) = elem };
    }

    pub fn size(&self) -> usize {
        let guard = epoch::pin();

        let descriptor = self.descriptor.load(Ordering::Acquire, &guard);
        let descriptor_deref = unsafe { descriptor.deref() };

        let mut size: usize = descriptor_deref.size.load(Ordering::Relaxed);

        if !unsafe { descriptor.deref() }
            .pending
            .load(Ordering::Acquire, &guard)
            .is_null()
        {
            size -= 1;
        }

        size
    }

    pub fn push_back(&mut self, elem: T) {
        todo!();
    }

    pub fn pop_back(&mut self) -> Option<T> {
        loop {
            let desc_cur = self.descriptor.clone();
            self.complete_write(desc_cur.clone());

            let guard = pin();
            let desc_cur_loaded = desc_cur.load(Ordering::Acquire, &guard);

            let cur_size = unsafe { desc_cur_loaded.deref() }
                .size
                .load(Ordering::Acquire);

            let elem = unsafe { self.at(cur_size).as_ref() }.copied();

            let desc_next_loaded = Atomic::new(Descriptor {
                size: AtomicUsize::new(cur_size - 1),
                counter: AtomicUsize::new(0),
                pending: Atomic::null(),
            })
            .load(Ordering::Acquire, &guard);

            if self
                .descriptor
                .compare_exchange_weak(
                    desc_cur_loaded,
                    desc_next_loaded,
                    Ordering::AcqRel,
                    Ordering::Relaxed,
                    &guard,
                )
                .is_ok()
            {
                return elem;
            }
        }
    }

    fn at<'a>(&'a mut self, i: usize) -> *mut T {
        let pos = i + FIRST_BUCKET_SIZE;
        let highest_bit = pos.highest_bit();
        // pos xor 2^{hb}
        let idx = pos ^ (1 << highest_bit);
        let bucket = self.buckets[(highest_bit - FIRST_BUCKET_SIZE.highest_bit()) as usize]
            .load(Ordering::Acquire);
        unsafe { (bucket as *mut T).offset(idx.try_into().unwrap()) }
    }

    fn complete_write(&mut self, writeop: Atomic<Descriptor<T>>) {
        let guard = epoch::pin();
        let writeop_deref = unsafe { writeop.load(Ordering::Relaxed, &guard).deref() };

        if !writeop_deref
            .pending
            .load(Ordering::Relaxed, &guard)
            .is_null()
        {
            let write_desc = &writeop_deref.pending;
            let derefed_write_desc = unsafe { write_desc.load(Ordering::Acquire, &guard).deref() };

            if let Ok(_) = derefed_write_desc.loc.compare_exchange(
                derefed_write_desc.cur,
                derefed_write_desc.next,
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                writeop_deref
                    .pending
                    .store(Shared::null(), Ordering::Release);
            }
        }
    }
}
