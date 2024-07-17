#pragma once
#include <sys/uio.h>

#include <fuse_kernel.h>
#include <stdlib.h>
#include <unistd.h>

#include <concepts>
#include <format>
#include <iostream>
#include <stdexcept>
#include <string>
#include <system_error>
#include <type_traits>
#include <utility>
#include <vector>

/**
 * Concept to differentiate between values that are provided as variable-sized
 * objects.
 */
template <typename U>
concept IsVariableSizedFuseStructure =
    requires(U a) {
	    {
		    a.data()
		    } -> std::convertible_to<const void *>;
	    {
		    a.size()
		    } -> std::convertible_to<std::size_t>;
    };

namespace {

/**
 * CRTP class for a fuse filesystems.
 *
 * This allows tiny implementations of FUSE filesystems.
 *
 * It is intended for simplicity and not performance.  If you care about
 * performance, libfuse provides a rich set of interfaces for writing
 * multithreaded FUSE filesystems.
 *
 * This interface currently supports read-only filesystems. It may be extended
 * in the future for read-write ones.
 *
 * The `T` template parameter is the class that inherits from this.  The
 * `Debug` parameter controls whether (very!) verbose logging is enabled.
 *
 * Users subclass this class and implement methods for handling each FUSE
 * request. NOTE: The return types of the overridden methods do *NOT* have to
 * match the ones in this class.  It is perfectly fine to return non-owning
 * wrappers, for example, in places where an owning object is returned in the
 * default case.
 */
template <typename T, bool Debug = false> class FuseFS {

    protected:
	/**
	 * Helper type for buffers of bytes.
	 */
	using Buffer = std::vector<char>;

	/**
	 * Error wrapper.  Most FUSE commands return either a value appended to
	 * the response, or an error code in the response header.
	 */
	template <typename U> using ErrorOr = std::variant<int32_t, U>;

	/**
	 * Log a debug message to standard output if compiled in debug mode,
	 * otherwise do nothing.
	 */
	template <typename... Args>
	void debug_message(std::string_view formatString, Args &&...args)
	{
		if constexpr (Debug) {
			std::cerr << std::vformat(formatString,
					 std::make_format_args(args...))
				  << std::endl;
		}
	}

    private:
	/**
	 * The file descriptor for /dev/fuse
	 */
	int fd = -1;

	/**
	 * The maximum size of a response.
	 */
	static constexpr size_t MaxReadSize = 128 * 1024;

	/**
	 * The maximum size of a write (the largest size of a message body from
	 * the kernel to the deamon).
	 */
	static constexpr size_t MaxWriteSize = 4 * 1024;

	/**
	 * Read a single message from the FUSE device and return it as a header
	 * and a buffer containing the variable-sized portion.
	 */
	std::pair<fuse_in_header, std::vector<char>> read_message()
	{
		fuse_in_header header;
		Buffer message;
		message.resize(MaxWriteSize);
		// The fuse protocol is horrible.  Each message must be read as
		// a single atomic transaction, but you don't know the size
		// until you've read the header and so we must reserve the
		// maximum space even though most messages are a few bytes.
		// If you read too little, the device returns ENODEV and then no
		// future reads succeed.
		while (true) {
			iovec iov[] = { { &header, sizeof(header) },
				{ message.data(), message.size() } };
			debug_message("readv iov[0] {{ {}, {} }}",
			    iov[0].iov_base, iov[0].iov_len);
			debug_message("readv iov[1] {{ {}, {} }}",
			    iov[1].iov_base, iov[1].iov_len);

			ssize_t ret = readv(fd, iov, 2);
			if (ret > 0) {
				message.resize(ret - sizeof(header));
				return { header, std::move(message) };
			}
			if (errno != EAGAIN) {
				throw std::system_error(errno,
				    std::generic_category(),
				    "Failed to read from FUSE device");
			}
		}
	}

	/**
	 * Write an error response to the FUSE daemon.  This takes the request's
	 * unique ID and the error code as arguments.
	 */
	void write_response_error(uint64_t unique, uint32_t error)
	{
		fuse_out_header out;
		out.len = sizeof(out);
		out.error = error;
		out.unique = unique;
		debug_message("Writing error {}", error);
		ssize_t ret = write(fd, &out, sizeof(out));
		if (ret < 0) {
			throw std::system_error(errno, std::generic_category(),
			    "Failed to write to FUSE device");
		}
	}

	/**
	 * Write a non-error response.  The body can be:
	 *
	 * - A `NoResult` tag type, in which case only the header is sent.
	 * - A (reference to an) object that conforms to the
	 *   `IsVariableSizedFuseStructure` concept, in which case the `data()`
	 *   and `size()` members are used to extract the payload.
	 * - Any other object type, in which case the object is sent as-is.
	 */
	template <typename U> void write_response(uint64_t unique, U &body)
	{
		// Type of the body, excluding qualifiers.
		using Body = std::remove_cvref_t<U>;
		// Is the body type something other than the no-result tag type?
		constexpr bool HasBody = !std::is_same_v<Body, NoResult>;

		// Construct the header
		fuse_out_header out;
		out.error = 0;
		out.unique = unique;
		// The size is initially just the header size.  This field is
		// updated if a payload is attached.
		out.len = sizeof(out);

		// Prepare the iovec.
		iovec iov[] = { { &out, sizeof(out) },
			{ &body, sizeof(body) } };

		// If this is a variable-sized structure, query it for the data
		// to send.
		if constexpr (IsVariableSizedFuseStructure<Body>) {
			iov[1] = { body.data(), body.size() };
			out.len += body.size();
		} else if constexpr (HasBody) {
			out.len += sizeof(body);
		}

		// Helper to print in the normal hex dump format.  This makes it
		// easy to compare the messages sent to the kernel against other
		// implementations (via ktrace).
		auto print_hex = [](void *ptr, size_t length) {
			if constexpr (Debug) {
				uint8_t *p = (uint8_t *)ptr;
				for (size_t i = 0; i < length; i++) {
					std::cerr << std::vformat("{:02x}",
					    std::make_format_args(p[i]));
					if (i % 2 == 1) {
						std::cerr << ' ';
					}
				}
				std::cerr << std::endl;
			}
		};
		debug_message("Writing response {}, size: {}", unique, out.len);
		debug_message("iov[0] {{ {}, {} }}", iov[0].iov_base,
		    iov[0].iov_len);
		print_hex(iov[0].iov_base, iov[0].iov_len);
		if (HasBody) {
			debug_message("iov[1] {{ {}, {} }}", iov[1].iov_base,
			    iov[1].iov_len);
			print_hex(iov[1].iov_base, iov[1].iov_len);
		}

		// We need to use writev because the FUSE device requires
		// messages to be written as a single transaction.
		ssize_t ret = writev(fd, iov, HasBody ? 2 : 1);
		// FUSE messages are written as a single atomic transaction,
		// they will never partially fail, the entire write will fail if
		// the FUSE device does not accept the message.  DTrace is your
		// friend if this happens.
		if (ret != out.len) {
			throw std::system_error(errno, std::generic_category(),
			    "Failed to write to FUSE device");
		}
	}

	/**
	 * Helper to extract the argument of a callback.  This version is never
	 * instantiated, only the specialisation is.
	 */
	template <typename U> struct CallbackArgumentType { };

	/**
	 * Specialisation for the method pointers that call the function.
	 */
	template <typename Base, typename ResultType, typename ArgumentType>
	struct CallbackArgumentType<ErrorOr<ResultType> (
	    Base::*)(const fuse_in_header &, ArgumentType)> {

		/// The type of the argument.
		using Argument = std::remove_cvref_t<ArgumentType>;
		/// The result type.
		using Result = ErrorOr<ResultType>;
		/// The result type removing the `ErrorOr` wrapper.
		using SuccessResultType = ResultType;
	};

	/**
	 * Specialisation for members that don't take a message-specific
	 * argument type (used for messages where the header is the only
	 * message).
	 */
	template <typename Base, typename ResultType>
	struct CallbackArgumentType<ErrorOr<ResultType> (Base::*)(
	    const fuse_in_header &)> {
		/// The type of the argument.
		using Argument = void;
		/// The result type.
		using Result = ErrorOr<ResultType>;
		/// The result type removing the `ErrorOr` wrapper.
		using SuccessResultType = ResultType;
	};

	/**
	 * Dispatch a message to the handler given by `function`.  This must be
	 * a member pointer for `T`.  The body will be coerced to the type that
	 * this function expects and then the response sent back to the kernel.
	 * The return type is expected to be an `ErrorOr` wrapper around the
	 * real return result.  If this contains the error code, that will be
	 * reported as an error, otherwise the payload will be returned.
	 *
	 * If the return type is the `NoResponse` tag type, no response is sent
	 * (not even the header).
	 */
	void dispatch(auto function, const fuse_in_header header,
	    const Buffer body)
	{
		// Extract the argument and result types from the pointer
		using Argument =
		    typename CallbackArgumentType<decltype(function)>::Argument;
		using Result =
		    typename CallbackArgumentType<decltype(function)>::Result;

		// Call the callback and get the result
		Result result;
		if constexpr (std::is_same_v<Argument, void>) {
			// If this doesn't take an extra argument, use the
			// one-argument version.
			result = ((static_cast<T *>(this))->*function)(header);
		} else if constexpr (std::is_pointer_v<Argument>) {
			// If the argument is a pointer, pass it directly.
			result = ((static_cast<T *>(this))->*function)(header,
			    reinterpret_cast<const Argument>(body.data()));
		} else {
			// If the argument type is not a pointer, convert the
			// pointer to a reference of the correct type and pass
			// that.
			const Argument &argument =
			    *reinterpret_cast<const Argument *>(body.data());
			result = ((static_cast<T *>(this))->*function)(header,
			    argument);
		}
		// Write the response back to the kernel.
		auto unique = header.unique;
		std::visit(
		    [unique, this](auto &&arg) {
			    if constexpr (std::is_same_v<uint32_t,
					      std::remove_cvref_t<
						  decltype(arg)>>) {
				    write_response_error(unique, arg);
			    } else if (!std::is_same_v<NoResponse,
					   std::remove_cvref_t<
					       decltype(arg)>>) {
				    write_response(unique, arg);
			    }
		    },
		    result);
	}

    public:
	/**
	 * Tag type for results where the FUSE response header is returned to
	 * the kernel with no additional data.
	 */
	struct NoResult { };

	/**
	 * Tag type for when no response should be given for a FUSE message.
	 */
	struct NoResponse { };

	/**
	 * Helper for building variable-sized responses.
	 */
	struct VariableSizeResponse : Buffer {
		/**
		 * Add an arbitrary object to this buffer.
		 */
		template <typename U>
		VariableSizeResponse &operator<<(const U &object)
			requires(std::is_trivially_copyable_v<U>)
		{
			const uint8_t *start =
			    reinterpret_cast<const uint8_t *>(&object);
			const uint8_t *end = start + sizeof(U);
			Buffer::insert(Buffer::end(), start, end);
			return *this;
		}

		/**
		 * Add a string view to this buffer.
		 */
		VariableSizeResponse &operator<<(std::string_view string)
		{
			Buffer::insert(Buffer::end(), string.begin(),
			    string.end());
			return *this;
		}

		/**
		 * Insert padding to ensure alignment (at the end, `size()` will
		 * return a multiple of `align`).
		 */
		void pad_to_alignment(size_t align)
		{
			while (size() % align != 0) {
				push_back(0);
			}
		}
	};

	/**
	 * Constructor.  Takes ownership of the filesystem given to us by
	 * `mount_fusefs`.
	 */
	FuseFS()
	{
		std::string fdName = getenv("FUSE_DEV_FD");
		if (fdName.empty()) {
			throw std::invalid_argument("FUSE_DEV_FD not set");
		}
		fd = std::stoi(fdName);
	}

	/**
	 * Destructor.
	 */
	~FuseFS()
	{
		if (fd != -1) {
			close(fd);
		}
	}

	/**
	 * Default handler for FUSE_INIT messages.  Sets some sensible defaults
	 * for the connection.  You can override this and either call this and
	 * modify the result, or replace it entirely.
	 */
	ErrorOr<fuse_init_out> fuse_init(const fuse_in_header &,
	    const fuse_init_in &initIn)
	{
		// If this is a very old FUSE version, give up.
		if ((initIn.major < 7) ||
		    ((initIn.major == 7) && (initIn.minor < 13))) {
			return ENOTSUP;
		}
		fuse_init_out reply;
		// Make sure any new fields are zero.
		memset(&reply, 0, sizeof(reply));
		reply.major = FUSE_KERNEL_VERSION;
		reply.minor = FUSE_KERNEL_MINOR_VERSION;
		reply.max_readahead = MaxReadSize;
		reply.congestion_threshold = 100;
		reply.max_background = 100;
		reply.max_write = MaxWriteSize;
		reply.time_gran = 1;
		debug_message("Initialised FUSE connection!");
		return reply;
	}

	/**
	 * Handler for FUSE_GETATTR messages.  Should be overridden by
	 * subclasses.
	 */
	ErrorOr<fuse_attr_out> fuse_getattr(const fuse_in_header &,
	    const fuse_getattr_in &)
	{
		return ENOTSUP;
	}

	/**
	 * Handler for FUSE_OPEN messages.  Should be overridden by subclasses.
	 */
	ErrorOr<fuse_open_out> fuse_open(const fuse_in_header &,
	    const fuse_open_in &)
	{
		return ENOTSUP;
	}

	/**
	 * Handler for FUSE_OPENDIR messages.  Should be overridden by
	 * subclasses.
	 */
	ErrorOr<fuse_open_out> fuse_opendir(const fuse_in_header &,
	    const fuse_open_in &)
	{
		return ENOTSUP;
	}

	/**
	 * Handler for FUSE_ACCESS messages.  This can return an error if access
	 * is not allowed, otherwise the VFS layer will perform normal access
	 * checks.
	 */
	ErrorOr<NoResult> fuse_access(const fuse_in_header &,
	    const fuse_access_in &)
	{
		// Allow anything.
		return NoResult {};
	}

	/**
	 * Handler for FUSE_RELEASE messages.  Should be overridden by
	 * subclasses that store any state per file descriptor.
	 */
	ErrorOr<NoResult> fuse_release(const fuse_in_header &,
	    const fuse_release_in &)
	{
		return NoResult {};
	}

	/**
	 * Handler for FUSE_OPENDIR messages.  Should be overridden by
	 * subclasses that store any state per directory descriptor.
	 */
	ErrorOr<NoResult> fuse_releasedir(const fuse_in_header &,
	    const fuse_release_in &)
	{
		return NoResult {};
	}

	/**
	 * Handler for FUSE_FORGET messages.  Can be overridden by subclasses.
	 */
	ErrorOr<NoResponse> fuse_forget(const fuse_in_header &,
	    const fuse_forget_in &)
	{
		return NoResponse {};
	}

	/**
	 * Handler for FUSE_READDIR messages.  Should be overridden by
	 * subclasses.
	 *
	 * The result is a sequence of `fuse_dirent` structures, followed by the
	 * name of the entry, padded to an 8-byte boundary.
	 */
	ErrorOr<VariableSizeResponse> fuse_readdir(const fuse_in_header &,
	    const fuse_read_in &)
	{
		return ENOTSUP;
	}

	/**
	 * Handler for FUSE_READ messages.  Should be overridden by subclasses.
	 */
	ErrorOr<VariableSizeResponse> fuse_read(const fuse_in_header &,
	    const fuse_read_in &)
	{
		return ENOTSUP;
	}

	/**
	 * Handler for FUSE_LOOKUP messages.  Should be overridden by
	 * subclasses.
	 */
	ErrorOr<fuse_entry_out> fuse_lookup(const fuse_in_header &,
	    const char *)
	{
		return ENOTSUP;
	}

	/**
	 * Handler for FUSE_FLUSH messages.  Can be overridden by subclasses.
	 */
	ErrorOr<NoResult> fuse_flush(const fuse_in_header &,
	    const fuse_flush_in &)
	{
		return NoResult {};
	}

	/**
	 * Handler for FUSE_SETATTR messages.  This is needed even for read-only
	 * filesystems unless they are mounted with noatime.  The default
	 * implementation returns a stub set of attributes with a cache policy
	 * indicating that they are immediately invalidated so the kernel will
	 * then query the daemon again to get the real values.  This is
	 * sufficient for read-only filesystems that don't support atime.
	 */
	ErrorOr<fuse_attr_out> fuse_setattr(const fuse_in_header &,
	    const fuse_setattr_in &)
	{
		// This requires a non-error response
		fuse_attr_out out;
		out.attr_valid = 0;
		out.attr_valid_nsec = 0;
		memset(&out.attr, 0, sizeof(out.attr));
		return out;
	}

	/**
	 * Handler for FUSE_READ messages.  Should be overridden by subclasses.
	 */
	ErrorOr<NoResult> fuse_read(const fuse_in_header &,
	    const fuse_flush_in &)
	{
		return NoResult {};
	}

	ErrorOr<fuse_statfs_out> fuse_statfs(const fuse_in_header &)
	{
		fuse_statfs_out out;
		memset(&out, 0, sizeof(out));
		out.st.blocks = 1;
		out.st.bfree = 0;
		out.st.bavail = 0;
		out.st.files = 0;
		out.st.ffree = 0;
		// Default block size
		out.st.bsize = 512;
		out.st.namelen = PATH_MAX;
		out.st.frsize = 0;
		return out;
	}

	/*
	 * Enter a run loop, waiting for kernel messages and posting responses.
	 *
	 * When a FUSE message is received from the kernel, this calls the
	 * corresponding handler in the subclass (or this class if none is
	 * provided in the subclass).
	 */
	void run()
	{
		debug_message("Starting FUSE FS");
		bool destroy = false;
		while (!destroy) {
			auto [header, body] = read_message();

			debug_message(
			    "Message: {{ opcode: {}, length: {}, unique: {}, nodeid: {}, uid: {}, gid: {}, pid: {} }}",
			    header.opcode, header.len, header.unique,
			    header.nodeid, header.uid, header.gid, header.pid);
			switch (header.opcode) {
			default:
				debug_message(
				    "Unhandled message with opcode {}",
				    header.opcode);
				write_response_error(header.unique, ENOTSUP);
				break;
			case FUSE_INIT:
				dispatch(&T::fuse_init, header, body);
				break;
			case FUSE_GETATTR:
				dispatch(&T::fuse_getattr, header, body);
				break;
			case FUSE_OPEN:
				dispatch(&T::fuse_open, header, body);
				break;
			case FUSE_OPENDIR:
				dispatch(&T::fuse_opendir, header, body);
				break;
			case FUSE_ACCESS:
				dispatch(&T::fuse_access, header, body);
				break;
			case FUSE_READDIR:
				dispatch(&T::fuse_readdir, header, body);
				break;
			case FUSE_READ:
				dispatch(&T::fuse_read, header, body);
				break;
			case FUSE_FORGET:
				dispatch(&T::fuse_forget, header, body);
				break;
			case FUSE_RELEASEDIR:
				dispatch(&T::fuse_releasedir, header, body);
				break;
			case FUSE_RELEASE:
				dispatch(&T::fuse_release, header, body);
				break;
			case FUSE_LOOKUP:
				dispatch(&T::fuse_lookup, header, body);
				break;
			case FUSE_FLUSH:
				dispatch(&T::fuse_flush, header, body);
				break;
			case FUSE_SETATTR:
				dispatch(&T::fuse_setattr, header, body);
				break;
			case FUSE_STATFS:
				dispatch(&T::fuse_statfs, header, body);
				break;
			case FUSE_DESTROY:
				// When we receive a destroy message, this
				// filesystem has been unmounted.  This doesn't
				// need a response, just close the device and
				// exit the run loop.
				close(fd);
				fd = -1;
				destroy = true;
				break;
			}
		}
	}
};

}
