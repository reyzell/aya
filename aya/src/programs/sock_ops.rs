//! Socket option programs.
use std::os::fd::AsFd;

use crate::{
    generated::{
        bpf_attach_type::BPF_CGROUP_SOCK_OPS, bpf_prog_type::BPF_PROG_TYPE_SOCK_OPS,
        BPF_F_ALLOW_OVERRIDE, BPF_F_ALLOW_MULTI,
    },
    programs::{
        define_link_wrapper, load_program, ProgAttachLink, ProgAttachLinkId, ProgramData,
        ProgramError,
    },
};

bitflags::bitflags! {
    /// Flags passed to [`SockOps::attach()`].
    #[derive(Clone, Copy, Debug, Default)]
    pub struct SockOpsFlags: u32 {
        /// Allow the eBPF program to be overridden by ones in a descendent cgroup.
        const ALLOW_OVERRIDE = BPF_F_ALLOW_OVERRIDE;
        /// Allow multiple eBPF programs to be attached.
       const ALLOW_MULTI = BPF_F_ALLOW_MULTI;
    }
}

/// A program used to work with sockets.
///
/// [`SockOps`] programs can access or set socket options, connection
/// parameters, watch connection state changes and more. They are attached to
/// cgroups.
///
/// # Minimum kernel version
///
/// The minimum kernel version required to use this feature is 4.13.
///
/// # Examples
///
/// ```no_run
/// # #[derive(thiserror::Error, Debug)]
/// # enum Error {
/// #     #[error(transparent)]
/// #     IO(#[from] std::io::Error),
/// #     #[error(transparent)]
/// #     Map(#[from] aya::maps::MapError),
/// #     #[error(transparent)]
/// #     Program(#[from] aya::programs::ProgramError),
/// #     #[error(transparent)]
/// #     Ebpf(#[from] aya::EbpfError)
/// # }
/// # let mut bpf = aya::Ebpf::load(&[])?;
/// use std::fs::File;
/// use aya::programs::SockOps;
///
/// let file = File::open("/sys/fs/cgroup/unified")?;
/// let prog: &mut SockOps = bpf.program_mut("intercept_active_sockets").unwrap().try_into()?;
/// prog.load()?;
/// prog.attach(file)?;
/// # Ok::<(), Error>(())
#[derive(Debug)]
#[doc(alias = "BPF_PROG_TYPE_SOCK_OPS")]
pub struct SockOps {
    pub(crate) data: ProgramData<SockOpsLink>,
}

impl SockOps {
    /// Loads the program inside the kernel.
    pub fn load(&mut self) -> Result<(), ProgramError> {
        load_program(BPF_PROG_TYPE_SOCK_OPS, &mut self.data)
    }

    /// Attaches the program to the given cgroup.
    ///
    /// The returned value can be used to detach, see [SockOps::detach].
    pub fn attach<T: AsFd>(&mut self, cgroup: T) -> Result<SockOpsLinkId, ProgramError> {
        self.attach_with_flags(cgroup, SockOpsFlags::empty())
    }

    /// Attaches the program to the given cgroup.
    ///
    /// The returned value can be used to detach, see [SockOps::detach].
    pub fn attach_with_flags<T: AsFd>(&mut self, cgroup: T, flags: SockOpsFlags) -> Result<SockOpsLinkId, ProgramError> {
        let prog_fd = self.fd()?;

        let link = ProgAttachLink::attach_with_flags(prog_fd.as_fd(), cgroup.as_fd(), BPF_CGROUP_SOCK_OPS, flags.bits())?;
        self.data.links.insert(SockOpsLink::new(link))
    }

    /// Detaches the program.
    ///
    /// See [SockOps::attach].
    pub fn detach(&mut self, link_id: SockOpsLinkId) -> Result<(), ProgramError> {
        self.data.links.remove(link_id)
    }

    /// Takes ownership of the link referenced by the provided link_id.
    ///
    /// The link will be detached on `Drop` and the caller is now responsible
    /// for managing its lifetime.
    pub fn take_link(&mut self, link_id: SockOpsLinkId) -> Result<SockOpsLink, ProgramError> {
        self.data.take_link(link_id)
    }
}

define_link_wrapper!(
    /// The link used by [SockOps] programs.
    SockOpsLink,
    /// The type returned by [SockOps::attach]. Can be passed to [SockOps::detach].
    SockOpsLinkId,
    ProgAttachLink,
    ProgAttachLinkId
);

#[cfg(test)]
mod tests {
    use super::SockOpsFlags;

    #[test]
    fn test_sock_ops_flags() {
        assert_eq!(SockOpsFlags::empty().bits(), 0);
        assert!(SockOpsFlags::ALLOW_OVERRIDE.bits() != 0);
        assert!(SockOpsFlags::ALLOW_MULTI.bits() != 0);
    }
}
