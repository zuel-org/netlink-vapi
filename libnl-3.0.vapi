/*
 * libnl-3.0.vapi
 *
 * Copyright (C) 2009-2015 Michael 'Mickey' Lauer <mlauer@vanille-media.de>
 * Copyright (C) 2011 Klaus Kurzmann <mok@fluxnetz.de>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.

 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.

 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA
 *
 */

 [CCode (lower_case_cprefix = "nl_", cheader_filename = "netlink/netlink.h")]
 namespace Netlink {

   
        
 
     [CCode (has_type_id = false, cname = "int")]
     public enum Protocol {
         [CCode (cname = "0")]
         NETLINK_ROUTE,		    /* Routing/device hook				*/
         [CCode (cname = "1")]
         NETLINK_UNUSED,		    /* Unused number				*/
         [CCode (cname = "2")]
         NETLINK_USERSOCK,		/* Reserved for user mode socket protocols 	*/
         [CCode (cname = "3")]
         NETLINK_FIREWALL,		/* Unused number, formerly ip_queue		*/
         [CCode (cname = "4")]
         NETLINK_SOCK_DIAG,		/* socket monitoring				*/
         [CCode (cname = "5")]
         NETLINK_NFLOG,		    /* netfilter/iptables ULOG */
         [CCode (cname = "6")]
         NETLINK_XFRM,		    /* ipsec */
         [CCode (cname = "7")]
         NETLINK_SELINUX,		/* SELinux event notifications */
         [CCode (cname = "8")]
         NETLINK_ISCSI,		    /* Open-iSCSI */
         [CCode (cname = "9")]
         NETLINK_AUDIT,		    /* auditing */
         [CCode (cname = "10")]
         NETLINK_FIB_LOOKUP,	
         [CCode (cname = "11")]
         NETLINK_CONNECTOR,	
         [CCode (cname = "12")]
         NETLINK_NETFILTER,	    /* netfilter subsystem */
         [CCode (cname = "13")]
         NETLINK_IP6_FW,	
         [CCode (cname = "14")]
         NETLINK_DNRTMSG,	    /* DECnet routing messages (obsolete) */
         [CCode (cname = "15")]
         NETLINK_KOBJECT_UEVENT,	/* Kernel messages to userspace */
         [CCode (cname = "16")]
         NETLINK_GENERIC,		
                                 /* leave room for NETLINK_DM (DM Events) */
         [CCode (cname = "18")]
         NETLINK_SCSITRANSPORT,	/* SCSI Transports */
         [CCode (cname = "19")]
         NETLINK_ECRYPTFS,	
         [CCode (cname = "20")]
         NETLINK_RDMA,		
         [CCode (cname = "21")]
         NETLINK_CRYPTO,	        /* Crypto layer */
         [CCode (cname = "22")]
         NETLINK_SMC,	        /* SMC monitoring */
         [CCode (cname = "4")]
         NETLINK_INET_DIAG
     }
 
     [CCode (cname = "nl_geterror", cheader_filename = "netlink/netlink.h")]
     public static unowned string strerror( int number );
 
     [CCode (instance_pos = -1)]
     public delegate void CallbackFunc (Object obj);
 
     [CCode (cname = "nl_recmsg_msg_cb_t", cheader_filename = "netlink/netlink.h", instance_pos = -1)]
     public delegate int MessageCallbackFunc (Message msg);
 
     [Compact]
     [CCode (cprefix = "nl_addr_", cname = "struct nl_addr", free_function = "nl_addr_put", cheader_filename = "netlink/netlink.h")]
     public class Address : Object {
         [CCode (cname = "nl_addr_alloc")]
         public Address();
 
         [CCode (cname = "nl_addr_build")]
         public static Address? build (int family, string buf, size_t size);
 
         public void     put();
 
         public int      set_label (string label);
         public unowned string   get_label ();
 
         public void     set_family (int family);
         public uint8      get_family ();
 
         public Netlink.Link? get_link ();
 
 
         public Netlink.Address? get_local();
         public Netlink.Address? get_peer();
         public Netlink.Address? get_broadcast();
         public Netlink.Address? get_anycast();
         public Netlink.Address? get_multicast();
 
         
 
 
         [CCode (cname = "nl_addr_get_len")]
         public int      get_len();
 
         [CCode (cname = "nl_addr_get_binary_addr")]
         public void*    get_binary_addr();
 
         [CCode (cname = "nl_addr2str")]
         public unowned string to_stringbuf(char[] buf);
 
         public string to_string() {
             char[] buf = new char[256];
             return to_stringbuf( buf );
         }
     }
 
     [Compact]
     [CCode (cprefix = "nla_", cname = "struct nlattr", free_function = "", cheader_filename = "netlink/netlink.h")]
     public class Attribute {
         public static int       attr_size (int payload);
         public static int       total_size (int payload);
         public static int       padlen (int payload);
 
         public int              type();
         public void*            data();
         public int              len();
         public int              ok (int remaining);
         public Attribute        next (out int remaining);
         public static int       parse (Attribute[] attributes, Attribute head, int len, AttributePolicy? policy = null);
         [CCode (cname="nla_parse_nested",instance_pos=1.5)]
         public int              parse_nested (Attribute[] attributes, AttributePolicy? policy = null);
         public int              validate (int len, int maxtype, AttributePolicy? policy = null);
         public Attribute        find (int len, int attrtype);

         public uint             get_u32();
         public ushort           get_u16();
         public uint8            get_u8();
         private char*           get_string();

         public string?          get_payload_string() {
            return (string?) get_string();
         }

         public uint8[]        get_data() {
            unowned uint8[] d = (uint8[]) data();
            d.length = len();
            return d;
         }
     }
 
     [Compact]
     [CCode (cname = "struct nla_policy", free_function = "")]
     public class AttributePolicy {
         [CCode (cname = "")]
         public AttributePolicy( AttributeType type = AttributeType.UNSPEC, uint16 minlen = 0, uint16 maxlen = 65535 )
         {
             this.type = type;
             this.minlen = minlen;
             this.maxlen = maxlen;
         }
         public uint16    type;
         public uint16    minlen;
         public uint16    maxlen;
     }
 
     [CCode (cprefix = "NLA_", cname = "int", cheader_filename = "netlink/attr.h", has_type_id = false)]
     public enum AttributeType {
         UNSPEC,     // Unspecified type, binary data chunk
         U8,         // 8 bit integer
         U16,        // 16 bit integer
         U32,        // 32 bit integer
         U64,        // 64 bit integer
         STRING,     // NUL terminated character string
         FLAG,       // Flag
         MSECS,      // Micro seconds (64bit)
         NESTED,     // Nested attributes
         TYPE_MAX
     }
 
     [Compact]
     [CCode (cprefix = "rtnl_addr_", cname = "struct rtnl_addr", free_function = "rtnl_addr_put", cheader_filename = "netlink/route/addr.h")]
     public class RouteAddress : Address {
         [CCode (cname = "rtnl_addr_alloc")]
         public RouteAddress();
 
         public void     set_ifindex (int index );
         public int      get_ifindex ();
 
         public void     set_scope (int scope);
         public int      get_scope ();
 
         public unowned Address get_local();
         public int             set_local(Address local);

         public void    set_link(Link link);

         public int      build_add_request (int a, out Message m);
         public int      build_delete_request (int a, out Message m);

         public void     set_prefixlen (int len);
         public int      get_prefixlen ();
     }
 
     [Compact]
     [CCode (cprefix = "nl_cache_", cname = "struct nl_cache", free_function = "nl_cache_free", cheader_filename = "netlink/netlink.h")]
     public class Cache {
         public static int alloc_name (string name, out Cache c);
 
         public void @foreach (CallbackFunc cb);
         public void foreach_filter (Object obj, CallbackFunc cb);
 
         public void  mngt_provide();
         public void  mngt_unprovide();
     }
 
     [CCode (cname = "int", cprefix = "NL_ACT_", has_type_id = false, cheader_filename = "netlink/cache.h")]
     public enum CacheAction {
         NEW,
         DEL,
         GET,
         SET,
         CHANGE,
     }
 
     [CCode (cname = "change_func_t", cheader_filename = "netlink/cache.h", instance_pos = -1)]
     public delegate void ChangeCallbackFunc (Cache cache, Object obj, CacheAction act);
 
     [Compact]
     [CCode (cprefix = "nl_cache_mngr_", cname = "struct nl_cache_mngr", free_function = "nl_cache_mngr_free", cheader_filename = "netlink/cache.h")]
     public class CacheManager {
         public static int alloc (Socket? sk, int protocol, int flags, out CacheManager c);
 
         public int add_cache(Cache cache, ChangeCallbackFunc cb);
         public int add(string name, ChangeCallbackFunc cb, out unowned Cache cache);
 
         public int get_fd();
         public int poll(int timeout);
 
         public int data_ready();
         public void info(DumpParams params);
     }
 
 
     [Compact]
     [CCode (cprefix = "nl_cb_", cname = "struct nl_cb", free_function = "nl_cb_put", cheader_filename = "netlink/netlink.h")]
     public class Callback {

        [CCode (cname = "nl_cb_clone")]
        public Callback         clone();

         [CCode (cname = "nl_cb_alloc")]
         public Callback (CallbackKind kind = CallbackKind.DEFAULT);
         [CCode (cname = "nl_cb_set")]
         public int @set (CallbackType type, CallbackKind kind, MessageCallbackFunc func);
         [CCode (cname = "nl_cb_set_all")]
         public int set_all (CallbackKind kind, MessageCallbackFunc func);
     }
 
     [CCode (cname = "enum nl_cb_action", cprefix = "NL_", cheader_filename = "netlink/netlink.h", has_type_id = false)]
     public enum CallbackAction {
         OK,         //   Proceed with whatever comes next.
         SKIP,       //   Skip this message.
         STOP,       //   Stop parsing altogether and discard remaining messages.
     }
 
     [CCode (cname = "enum nl_cb_kind", cprefix = "NL_CB_", cheader_filename = "netlink/netlink.h", has_type_id = false)]
     public enum CallbackKind {
         DEFAULT,    // 	 Default handlers (quiet).
         VERBOSE,    // 	 Verbose default handlers (error messages printed).
         DEBUG,      // 	 Debug handlers for debugging.
         CUSTOM,     // 	 Customized handler specified by the user.
     }
 
     [CCode (cname = "enum nl_cb_type", cprefix = "NL_CB_", cheader_filename = "netlink/netlink.h", has_type_id = false)]
     public enum CallbackType {
         VALID,      // 	 Message is valid.
         FINISH,     // 	 Last message in a series of multi part messages received.
         OVERRUN,    // 	 Report received that data was lost.
         SKIPPED,    // 	 Message wants to be skipped.
         ACK,        // 	 Message is an acknowledge.
         MSG_IN,     // 	 Called for every message received.
         MSG_OUT,    // 	 Called for every message sent out except for nl_sendto().
         INVALID,    // 	 Message is malformed and invalid.
         SEQ_CHECK,  // 	 Called instead of internal sequence number checking.
         SEND_ACK,   // 	 Sending of an acknowledge message has been requested.
     }
 
     [Compact]
     [CCode (cprefix = "nl_link_cache_", cname = "struct nl_cache", free_function = "nl_cache_free", cheader_filename = "netlink/netlink.h")]
     public class LinkCache : Cache
     {
         [CCode (cname = "rtnl_link_name2i")]
         public int name2i (string name);
         [CCode (cname = "rtnl_link_i2name")]
         public unowned string i2name( int idx, char[] buffer );
         [CCode (cname = "rtnl_link_get")]
         public CachedLink? get(int idx);
         [CCode (cname = "rtnl_link_get_by_name")]
         public CachedLink? get_by_name(string idx);
     }
 
     [Compact]
     [CCode (cprefix = "nl_addr_cache", cname = "struct nl_cache", free_function = "nl_cache_free", cheader_filename = "netlink/netlink.h")]
     public class AddrCache : Cache
     {
     }
 
     [Compact]
     [CCode (cprefix = "nlmsg_", cname = "struct nl_msg", free_function = "nlmsg_free", cheader_filename = "netlink/netlink.h")]
     public class Message
     {
        [CCode (cname = "nlmsg_alloc", cheader_filename = "netlink/genl/genl.h")]
        public Message();

        [CCode (cname = "0")]
        public const int NL_AUTO_PORT;

        [CCode (cname = "0")]
        public const int NL_AUTO_SEQ;

         public void             dump (Posix.FILE file);
         public int              parse (CallbackFunc func);
         [CCode (cname = "nlmsg_hdr")]
         public MessageHeader    header ();

         [CCode (cname = "genlmsg_put")]
         public void put(int port, int seq, int family, int hdrlen, int flags, uint8 cmd, uint8 version);

         [CCode (cname = "nla_put")]
         private int nla_put(int attrtype, int datalen, void* data);

         [CCode (cname = "nla_put_nested")]
         public int put_nested(int attrtype, Netlink.Message message);

         [CCode (cname = "nla_put_u32")]
         public int put_uint_attribute(int attrtype, uint value);

         public int put_attribute(int attrtype, uint8[] data) {
            return nla_put(attrtype, data.length, data);

         }

         [CCode (cname = "nla_put_string")]
         public int put_string(int attrtype,string str);

     }

     [Compact]
     [CCode (cprefix = "genlmsg_", cname = "struct genlmsghdr", free_function = "", cheader_filename = "netlink/netlink.h")]
     public class GenericMessageHeader : MessageHeader
     {
        public int cmd;
         // attribute access
         public Attribute        attrdata (int hdrlen);
         public int              attrlen (int hdrlen);

     }
 
     [Compact]
     [CCode (cprefix = "nlmsg_", cname = "struct nlmsghdr", free_function = "", cheader_filename = "netlink/netlink.h")]
     public class MessageHeader
     {

        [CCode (has_type_id = false, cname = "int")]
        public enum Flags {
            [CCode (cname = "1")]
            NLM_F_REQUEST,  	/* It is request message. 	*/
            [CCode (cname = "2")]
            NLM_F_MULTI,    	/* Multipart message, terminated by NLMSG_DONE */
            [CCode (cname = "4")]
            NLM_F_ACK,		   	/* Reply with ack, with zero or error code */
            [CCode (cname = "8")]
            NLM_F_ECHO,		 	/* Receive resulting notifications */
            [CCode (cname = "16")]
            NLM_F_DUMP_INTR,	/* Dump was inconsistent due to sequence change */
            [CCode (cname = "32")]
            NLM_F_DUMP_FILTERED,/* Dump was filtered as requested */
            [CCode (cname = "256")]
            NLM_F_ROOT,
            [CCode (cname = "512")]
            NLM_F_MATCH,
            [CCode (cname = "1024")]
            NLM_F_ATOMIC,
            [CCode (cname = "768")]
            NLM_F_DUMP,

            /* Modifiers to NEW request */
            [CCode (cname = "256")]
            NLM_F_REPLACE,
            [CCode (cname = "512")]
            NLM_F_EXCL,
            [CCode (cname = "1024")]
            NLM_F_CREATE,
            [CCode (cname = "2048")]
            NLM_F_APPEND
        }

         // field access
         public uint32 nlmsg_len;
         public uint16 nlmsg_type;
         public uint16 nlmsg_flags;
         public uint32 nlmsg_seq;
         public uint32 nlmsg_pid;
 
         // size calculations
         public static int       msg_size (int payload);
         public static int       total_size (int payload);
         public static int       padlen (int payload);
 
         // payload access
         public GenericMessageHeader            data ();
         public int              datalen ();
         public void*            tail ();
 
        
 
         // message parsing
         public bool             valid_hdr (int hdrlen);
         public bool             ok (int remaining);
         public MessageHeader    next (out int remaining);
         public int              parse (int hdrlen, [CCode (array_length = "false")] out Attribute[] attributes, AttributeType maxtype, AttributePolicy? policy = null);
         public Attribute?       find_attr (int hdrlen, AttributeType type);
         public int              validate (int hdrlen, AttributeType maxtype, AttributePolicy policy);
     }
 
     [Compact]
     [CCode (cprefix = "nl_socket_", cname = "struct nl_sock", free_function = "nl_socket_free")]
     public class Socket {
         [CCode (cname = "nl_socket_alloc")]
         public Socket();
 
         [CCode (cname = "rtnl_link_alloc_cache")]
         public int              link_alloc_cache (int family, out LinkCache c);
         [CCode (cname = "rtnl_addr_alloc_cache")]
         public int              addr_alloc_cache (out AddrCache c);
         [CCode (cname = "rtnl_route_alloc_cache")]
         public int              route_alloc_cache (int family, int flags, out RouteCache c);
 
         // connection management
         [CCode (cname = "nl_close")]
         public int              close ();
         [CCode (cname = "nl_connect")]
         public int              connect (Netlink.Protocol protocol);

         [CCode (cname = "genl_connect")]
         public int              generic_connect ();

         [CCode (cname = "nl_send_auto")]
         public int              send_auto(Netlink.Message msg);
 
         // group management
         public int              add_memberships (int group, ...);
         public int              add_membership (int group);
         public int              drop_memberships (int group, ...);
         public int              drop_membership (int group);
         public uint32           get_peer_port ();
         public void             set_peer_port (uint32 port);
 
         // callback management
         public Callback         get_cb ();
         public void             set_cb (Callback cb);
         public int              modify_cb (CallbackType type, CallbackKind kind, MessageCallbackFunc callback);
 
         // configuration
         public int              set_buffer_size (int rxbuf, int txbuf);
         public int              set_passcred (bool on);
         public int              recv_pktinfo (bool on);
 
         public void             disable_seq_check ();
         public uint             use_seq ();
         public void             disable_auto_ack ();
         public void             enable_auto_ack ();
 
         public int              get_fd ();
         public int              set_nonblocking ();
         public void             enable_msg_peek ();
         public void             disable_msg_peek ();
 
         // receiving messages
         [CCode (cname = "nl_recv")]
         public int              recv (out Linux.Netlink.SockAddrNl addr, out char[] buf, out Linux.Socket.ucred cred);
 
         [CCode (cname = "nl_recvmsgs")]
         public int              recvmsgs (Callback cb);

         [CCode (cname = "nl_recvmsgs_report")]
         public int              recvmsgs_report (Callback cb);
 
         [CCode (cname = "nl_recvmsgs_default")]
         public int              recvmsgs_default ();
 
         [CCode (cname = "nl_wait_for_ack")]
         public int              wait_for_ack ();

         [CCode (cname = "genl_ctrl_resolve")]
         public int 	         controller_resolve (string name);
         
         [CCode (cname = "genl_ctrl_resolve_grp")]
         public int 	         controller_resolve_group (string name, string group);

     }
 
     [Compact]
     [CCode (cprefix = "nl_object_", cname = "struct nl_object", free_function = "nl_object_free", cheader_filename = "netlink/object.h")]
     public class Object
     {
         public uint32 ce_mask;
 
         public unowned string attrs2str	(uint32 attrs, char[] buf);
         public unowned string attr_list (char[] buf);
         public void dump (DumpParams params);
 
     }
 
     [CCode (cprefix = "NL_DUMP_", cname = "int", cheader_filename = "netlink/types.h", has_type_id = false)]
     public enum DumpType {
         LINE,           // Dump object briefly on one line
         DETAILS,        // Dump all attributes but no statistics
         STATS,          // Dump all attributes including statistics
     }
 
     [CCode (cname = "struct nl_dump_params", free_function = "", cheader_filename = "netlink/types.h", has_type_id = false)]
     public struct DumpParams {
         public DumpType dp_type;
         public int dp_prefix;
         public bool dp_print_index;
         public bool dp_dump_msgtype;
         public unowned Posix.FILE dp_fd;
         public unowned string dp_buf;
         public size_t dp_buflen;
     }
 
     [Compact]
     [CCode (cprefix = "rtnl_link_", cname = "struct rtnl_link", free_function = "rtnl_link_put", cheader_filename = "netlink/route/link.h")]
     public class Link {   

      [CCode (cname = "rtnl_link_alloc")]
      public Link();
 
      
      [CCode (has_type_id = false, cname = "int")]
      public enum DeviceFlags {
         [CCode (cname = "1")]
         IFF_UP				= 1<<0,  /* sysfs */
         [CCode (cname = "2")]
         IFF_BROADCAST			= 1<<1,  /* volatile */
         [CCode (cname = "4")]
         IFF_DEBUG			= 1<<2,  /* sysfs */
         [CCode (cname = "8")]
         IFF_LOOPBACK			= 1<<3,  /* volatile */
         [CCode (cname = "16")]
         IFF_POINTOPOINT			= 1<<4,  /* volatile */
         [CCode (cname = "32")]
         IFF_NOTRAILERS			= 1<<5,  /* sysfs */
         [CCode (cname = "64")]
         IFF_RUNNING			= 1<<6,  /* volatile */
         [CCode (cname = "128")]
         IFF_NOARP			= 1<<7,  /* sysfs */
         [CCode (cname = "256")]
         IFF_PROMISC			= 1<<8,  /* sysfs */
         [CCode (cname = "512")]
         IFF_ALLMULTI			= 1<<9,  /* sysfs */
         [CCode (cname = "1024")]
         IFF_MASTER			= 1<<10, /* volatile */
         [CCode (cname = "2048")]
         IFF_SLAVE			= 1<<11, /* volatile */
         [CCode (cname = "4096")]
         IFF_MULTICAST			= 1<<12, /* sysfs */
         [CCode (cname = "8192")]
         IFF_PORTSEL			= 1<<13, /* sysfs */
         [CCode (cname = "16384")]
         IFF_AUTOMEDIA			= 1<<14, /* sysfs */
         [CCode (cname = "32768")]
         IFF_DYNAMIC			= 1<<15, /* sysfs */
         [CCode (cname = "65536")]
         IFF_LOWER_UP			= 1<<16, /* volatile */
         [CCode (cname = "131072")]
         IFF_DORMANT			= 1<<17, /* volatile */
         [CCode (cname = "262144")]
         IFF_ECHO			= 1<<18, /* volatile */
      }
         
         public unowned string get_name();
         public unowned Netlink.Address? get_addr();
         public void set_addr(Netlink.Address addr);
         public Netlink.Address? get_broadcast();
         public uint get_flags();
         public void set_flags(Link.DeviceFlags flags);
         public void unset_flags(Link.DeviceFlags flags);
         public int get_family();
         public uint get_arptype();
         public int get_ifindex();
         public uint get_mtu();
         public uint get_txqlen();
         public uint get_weight();
         public unowned string? get_qdisc();
         public int  build_change_request (Link changes, MessageHeader.Flags flags, out Message m);
     }
 
     [Compact]
     [CCode (cprefix = "rtnl_link_", cname = "struct rtnl_link", free_function = "rtnl_link_put", cheader_filename = "netlink/route/link.h")]
     public class CachedLink : Link
     {
     }
     
     [Compact]
     [CCode (cprefix = "nl_route_cache_", cname = "struct nl_cache", free_function = "nl_cache_free", cheader_filename = "netlink/netlink.h")]
     public class RouteCache : Cache
     {
         
     }
 
 
 
     [Compact]
     [CCode (cprefix = "rtnl_route_", cname = "struct rtnl_route", free_function = "rtnl_route_put", cheader_filename = "netlink/route/route.h")]
     public class Route
     {
         [CCode (has_type_id = false, cname = "int")]
         public enum Scope {
             [CCode (cname = "0")]
             RT_SCOPE_UNIVERSE,
             /* User defined values  */
             [CCode (cname = "200")]
             RT_SCOPE_SITE,
             [CCode (cname = "253")]
             RT_SCOPE_LINK,
             [CCode (cname = "254")]
             RT_SCOPE_HOST,
             [CCode (cname = "255")]
             RT_SCOPE_NOWHERE
         }
 
         public enum Table {
             [CCode (cname = "0")]
             RT_TABLE_UNSPEC,
             [CCode (cname = "252")]
             RT_TABLE_COMPAT,
             [CCode (cname = "253")]
             RT_TABLE_DEFAULT,
             [CCode (cname = "254")]
             RT_TABLE_MAIN,
             [CCode (cname = "255")]
             RT_TABLE_LOCAL,
             [CCode (cname = "0xFFFFFFFF")]
             RT_TABLE_MAX
         }
 
         [CCode (cname = "rtnl_route_alloc")]
         public Route();
 
         public uint32 get_table();
         public uint8 get_scope();
         public uint8 get_tos();
         public uint8 get_protocol();
         public uint32 get_priority();
         public uint8 get_family();
         public void set_family(int family);
         public Netlink.Address? get_dst();
         public void set_dst(Netlink.Address dst);
 
         public void set_scope(Route.Scope scope);
         public void set_table(Route.Table table);
 
         public Netlink.Address? get_src();
         public uint8 get_type();
         public uint32 get_flags();
         public int get_metric();
         public Netlink.Address? get_pref_src();
         public int get_iif();
         public void foreach_nexthop(CallbackFunc cb);
     }
 
     [CCode (cprefix = "rtnl_route_nh_", cname = "struct rtnl_nexthop", free_function = "rtnl_route_nh_free", cheader_filename = "netlink/netlink.h")]
     public class NextHop : Object {
         [CCode (cname = "rtnl_route_nh_alloc")]
         public NextHop();
 
         public void set_weight (uint8 weight);
         public uint8 get_weight ();
         public void set_ifindex ();
         public int get_ifindex ();
         public void set_gateway (Netlink.Address addr);
         public unowned Netlink.Address? get_gateway ();
         public void set_flags (uint flags);
         public void unset_flags (uint flags);
         public uint get_flags ();
         public void set_realms (int realms);
     }
 
     [Compact]
     [CCode (cprefix = "rtnl_neigh_", cname = "struct rtnl_neigh", cheader_filename = "netlink/route/neighbour.h")]
     public class Neighbour
     {
         public int get_state();
         public uint get_flags();
         public int get_ifindex();
         public Netlink.Address? get_lladdr();
         public Netlink.Address? get_dst();
         public int get_type();
         public int get_family();
     }
 
     [Compact]
     [CCode (cprefix = "rtnl_rule_", cname = "struct rtnl_rule", cheader_filename = "netlink/route/rule.h")]
     public class Rule
     {
         public int get_family();
         public uint32 get_prio();
         public uint32 get_mark();
         public uint32 get_mask();
         public uint32 get_table();
         public uint8 get_dsfield();
         public Netlink.Address? get_src();
         public Netlink.Address? get_dst();
         public uint8 get_action();
         public unowned string? get_iif();
         public unowned string? get_oif();
         public uint32 get_realms();
         public uint32 get_goto();
     }
 
     [Compact]
     [CCode (cprefix = "rtnl_qdisc_", cname = "struct rtnl_qdisc", cheader_filename = "netlink/route/qdisc.h")]
     public class Qdisc
     {
         public int get_ifindex();
         public uint32 get_handle();
         public uint32 get_parent();
         public unowned string? get_kind();
         public uint64 get_stat();
     }
 
     [CCode (cname = "nl_nlmsgtype2str", cheader_filename = "netlink/msg.h")]
     public unowned string msgType2Str( int type, char[] buf );
     [CCode (cname = "nl_af2str", cheader_filename = "netlink/addr.h")]
     public unowned string af2Str( int family, char[] buf );
     [CCode (cname = "nl_llproto2str", cheader_filename = "netlink/utils.h")]
     public unowned string llproto2Str( uint proto, char[] buf );
     [CCode (cname = "rtnl_link_flags2str", cheader_filename = "netlink/route/link.h")]
     public unowned string linkFlags2Str( uint flags, char[] buf );
     [CCode (cname = "rtnl_scope2str", cheader_filename = "netlink/route/rtnl.h")]
     public unowned string routeScope2Str( int scope, char[] buf );
     [CCode (cname = "nl_rtntype2str", cheader_filename = "netlink/netlink.h")]
     public unowned string routeType2Str( int type, char[] buf );
     [CCode (cname = "rtnl_addr_flags2str", cheader_filename = "netlink/netlink.h")]
     public unowned string addrFlags2Str( int flags, char[] buf );
     [CCode (cname = "rtnl_neigh_flags2str", cheader_filename = "netlink/netlink.h")]
     public unowned string neighFlags2Str( uint flags, char[] buf );
     [CCode (cname = "rtnl_neigh_state2str", cheader_filename = "netlink/netlink.h")]
     public unowned string neighState2Str( int state, char[] buf );
 
 }

 namespace NL80211 {
    [CCode (has_type_id = false, cname = "int")]
    enum Attribute {
        /* don't change the order or add anything inbetween, this is ABI! */
        [CCode (cname = "0")]
        NL80211_ATTR_UNSPEC,
    
     [CCode (cname = "1")]
        NL80211_ATTR_WIPHY,
    
     [CCode (cname = "2")]
        NL80211_ATTR_WIPHY_NAME,
    
     [CCode (cname = "3")]
        NL80211_ATTR_IFINDEX,
    
     [CCode (cname = "4")]
        NL80211_ATTR_IFNAME,
    
     [CCode (cname = "5")]
        NL80211_ATTR_IFTYPE,
    
     [CCode (cname = "6")]
        NL80211_ATTR_MAC,
    
     [CCode (cname = "7")]
        NL80211_ATTR_KEY_DATA,
    
     [CCode (cname = "8")]
        NL80211_ATTR_KEY_IDX,
    
     [CCode (cname = "9")]
        NL80211_ATTR_KEY_CIPHER,
    
     [CCode (cname = "10")]
        NL80211_ATTR_KEY_SEQ,
    
     [CCode (cname = "11")]
        NL80211_ATTR_KEY_DEFAULT,
    
     [CCode (cname = "12")]
        NL80211_ATTR_BEACON_INTERVAL,
    
     [CCode (cname = "13")]
        NL80211_ATTR_DTIM_PERIOD,
    
     [CCode (cname = "14")]
        NL80211_ATTR_BEACON_HEAD,
    
     [CCode (cname = "15")]
        NL80211_ATTR_BEACON_TAIL,
    
     [CCode (cname = "16")]
        NL80211_ATTR_STA_AID,
    
     [CCode (cname = "17")]
        NL80211_ATTR_STA_FLAGS,
    
     [CCode (cname = "18")]
        NL80211_ATTR_STA_LISTEN_INTERVAL,
    
     [CCode (cname = "19")]
        NL80211_ATTR_STA_SUPPORTED_RATES,
    
     [CCode (cname = "20")]
        NL80211_ATTR_STA_VLAN,
    
     [CCode (cname = "21")]
        NL80211_ATTR_STA_INFO,
    
     [CCode (cname = "22")]
        NL80211_ATTR_WIPHY_BANDS,
    
     [CCode (cname = "23")]
        NL80211_ATTR_MNTR_FLAGS,
    
     [CCode (cname = "24")]
        NL80211_ATTR_MESH_ID,
    
     [CCode (cname = "25")]
        NL80211_ATTR_STA_PLINK_ACTION,
    
     [CCode (cname = "26")]
        NL80211_ATTR_MPATH_NEXT_HOP,
    
     [CCode (cname = "27")]
        NL80211_ATTR_MPATH_INFO,
    
     [CCode (cname = "28")]
        NL80211_ATTR_BSS_CTS_PROT,
    
     [CCode (cname = "29")]
        NL80211_ATTR_BSS_SHORT_PREAMBLE,
    
     [CCode (cname = "30")]
        NL80211_ATTR_BSS_SHORT_SLOT_TIME,
    
     [CCode (cname = "31")]
        NL80211_ATTR_HT_CAPABILITY,
    
     [CCode (cname = "32")]
        NL80211_ATTR_SUPPORTED_IFTYPES,
    
     [CCode (cname = "33")]
        NL80211_ATTR_REG_ALPHA2,
    
     [CCode (cname = "34")]
        NL80211_ATTR_REG_RULES,
    
     [CCode (cname = "35")]
        NL80211_ATTR_MESH_CONFIG,
    
     [CCode (cname = "36")]
        NL80211_ATTR_BSS_BASIC_RATES,
    
     [CCode (cname = "37")]
        NL80211_ATTR_WIPHY_TXQ_PARAMS,
    
     [CCode (cname = "38")]
        NL80211_ATTR_WIPHY_FREQ,
    
     [CCode (cname = "39")]
        NL80211_ATTR_WIPHY_CHANNEL_TYPE,
    
     [CCode (cname = "40")]
        NL80211_ATTR_KEY_DEFAULT_MGMT,
    
     [CCode (cname = "41")]
        NL80211_ATTR_MGMT_SUBTYPE,
    
     [CCode (cname = "42")]
        NL80211_ATTR_IE,
    
     [CCode (cname = "43")]
        NL80211_ATTR_MAX_NUM_SCAN_SSIDS,
    
     [CCode (cname = "44")]
        NL80211_ATTR_SCAN_FREQUENCIES,
    
     [CCode (cname = "45")]
        NL80211_ATTR_SCAN_SSIDS,
    
     [CCode (cname = "46")]
        NL80211_ATTR_GENERATION, /* replaces old SCAN_GENERATION */
    
     [CCode (cname = "47")]
        NL80211_ATTR_BSS,
    
     [CCode (cname = "48")]
        NL80211_ATTR_REG_INITIATOR,
    
     [CCode (cname = "49")]
        NL80211_ATTR_REG_TYPE,
    
     [CCode (cname = "50")]
        NL80211_ATTR_SUPPORTED_COMMANDS,
    
     [CCode (cname = "51")]
        NL80211_ATTR_FRAME,
    
     [CCode (cname = "52")]
        NL80211_ATTR_SSID,
    
     [CCode (cname = "53")]
        NL80211_ATTR_AUTH_TYPE,
    
     [CCode (cname = "54")]
        NL80211_ATTR_REASON_CODE,
    
     [CCode (cname = "55")]
        NL80211_ATTR_KEY_TYPE,
    
     [CCode (cname = "56")]
        NL80211_ATTR_MAX_SCAN_IE_LEN,
    
     [CCode (cname = "57")]
        NL80211_ATTR_CIPHER_SUITES,
    
     [CCode (cname = "58")]
        NL80211_ATTR_FREQ_BEFORE,
    
     [CCode (cname = "59")]
        NL80211_ATTR_FREQ_AFTER,
    
     [CCode (cname = "60")]
        NL80211_ATTR_FREQ_FIXED,
    
     [CCode (cname = "61")]
        NL80211_ATTR_WIPHY_RETRY_SHORT,
    
     [CCode (cname = "62")]
        NL80211_ATTR_WIPHY_RETRY_LONG,
    
     [CCode (cname = "63")]
        NL80211_ATTR_WIPHY_FRAG_THRESHOLD,
    
     [CCode (cname = "64")]
        NL80211_ATTR_WIPHY_RTS_THRESHOLD,
    
     [CCode (cname = "65")]
        NL80211_ATTR_TIMED_OUT,
    
     [CCode (cname = "66")]
        NL80211_ATTR_USE_MFP,
    
     [CCode (cname = "67")]
        NL80211_ATTR_STA_FLAGS2,
    
     [CCode (cname = "68")]
        NL80211_ATTR_CONTROL_PORT,
    
     [CCode (cname = "69")]
        NL80211_ATTR_TESTDATA,
    
     [CCode (cname = "70")]
        NL80211_ATTR_PRIVACY,
    
     [CCode (cname = "71")]
        NL80211_ATTR_DISCONNECTED_BY_AP,
    
     [CCode (cname = "72")]
        NL80211_ATTR_STATUS_CODE,
    
     [CCode (cname = "73")]
        NL80211_ATTR_CIPHER_SUITES_PAIRWISE,
    
     [CCode (cname = "74")]
        NL80211_ATTR_CIPHER_SUITE_GROUP,
    
     [CCode (cname = "75")]
        NL80211_ATTR_WPA_VERSIONS,
    
     [CCode (cname = "76")]
        NL80211_ATTR_AKM_SUITES,
    
     [CCode (cname = "77")]
        NL80211_ATTR_REQ_IE,
    
     [CCode (cname = "78")]
        NL80211_ATTR_RESP_IE,
    
     [CCode (cname = "79")]
        NL80211_ATTR_PREV_BSSID,
    
     [CCode (cname = "80")]
        NL80211_ATTR_KEY,
    
     [CCode (cname = "81")]
        NL80211_ATTR_KEYS,
    
     [CCode (cname = "82")]
        NL80211_ATTR_PID,
    
     [CCode (cname = "83")]
        NL80211_ATTR_4ADDR,
    
     [CCode (cname = "84")]
        NL80211_ATTR_SURVEY_INFO,
    
     [CCode (cname = "85")]
        NL80211_ATTR_PMKID,
    
     [CCode (cname = "86")]
        NL80211_ATTR_MAX_NUM_PMKIDS,
    
     [CCode (cname = "87")]
        NL80211_ATTR_DURATION,
    
     [CCode (cname = "88")]
        NL80211_ATTR_COOKIE,
    
     [CCode (cname = "89")]
        NL80211_ATTR_WIPHY_COVERAGE_CLASS,
    
     [CCode (cname = "90")]
        NL80211_ATTR_TX_RATES,
    
     [CCode (cname = "91")]
        NL80211_ATTR_FRAME_MATCH,
    
     [CCode (cname = "92")]
        NL80211_ATTR_ACK,
    
     [CCode (cname = "93")]
        NL80211_ATTR_PS_STATE,
    
     [CCode (cname = "94")]
        NL80211_ATTR_CQM,
    
     [CCode (cname = "95")]
        NL80211_ATTR_LOCAL_STATE_CHANGE,
    
     [CCode (cname = "96")]
        NL80211_ATTR_AP_ISOLATE,
    
     [CCode (cname = "97")]
        NL80211_ATTR_WIPHY_TX_POWER_SETTING,
    
     [CCode (cname = "98")]
        NL80211_ATTR_WIPHY_TX_POWER_LEVEL,
    
     [CCode (cname = "99")]
        NL80211_ATTR_TX_FRAME_TYPES,
    
     [CCode (cname = "100")]
        NL80211_ATTR_RX_FRAME_TYPES,
    
     [CCode (cname = "101")]
        NL80211_ATTR_FRAME_TYPE,
    
     [CCode (cname = "102")]
        NL80211_ATTR_CONTROL_PORT_ETHERTYPE,
    
     [CCode (cname = "103")]
        NL80211_ATTR_CONTROL_PORT_NO_ENCRYPT,
    
     [CCode (cname = "104")]
        NL80211_ATTR_SUPPORT_IBSS_RSN,
    
     [CCode (cname = "105")]
        NL80211_ATTR_WIPHY_ANTENNA_TX,
    
     [CCode (cname = "106")]
        NL80211_ATTR_WIPHY_ANTENNA_RX,
    
     [CCode (cname = "107")]
        NL80211_ATTR_MCAST_RATE,
    
     [CCode (cname = "108")]
        NL80211_ATTR_OFFCHANNEL_TX_OK,
    
     [CCode (cname = "109")]
        NL80211_ATTR_BSS_HT_OPMODE,
    
     [CCode (cname = "110")]
        NL80211_ATTR_KEY_DEFAULT_TYPES,
    
     [CCode (cname = "111")]
        NL80211_ATTR_MAX_REMAIN_ON_CHANNEL_DURATION,
    
     [CCode (cname = "112")]
        NL80211_ATTR_MESH_SETUP,
    
     [CCode (cname = "113")]
        NL80211_ATTR_WIPHY_ANTENNA_AVAIL_TX,
    
     [CCode (cname = "114")]
        NL80211_ATTR_WIPHY_ANTENNA_AVAIL_RX,
    
     [CCode (cname = "115")]
        NL80211_ATTR_SUPPORT_MESH_AUTH,
    
     [CCode (cname = "116")]
        NL80211_ATTR_STA_PLINK_STATE,
    
     [CCode (cname = "117")]
        NL80211_ATTR_WOWLAN_TRIGGERS,
    
     [CCode (cname = "118")]
        NL80211_ATTR_WOWLAN_TRIGGERS_SUPPORTED,
    
     [CCode (cname = "119")]
        NL80211_ATTR_SCHED_SCAN_INTERVAL,
    
     [CCode (cname = "120")]
        NL80211_ATTR_INTERFACE_COMBINATIONS,
    
     [CCode (cname = "121")]
        NL80211_ATTR_SOFTWARE_IFTYPES,
    
     [CCode (cname = "122")]
        NL80211_ATTR_REKEY_DATA,
    
     [CCode (cname = "123")]
        NL80211_ATTR_MAX_NUM_SCHED_SCAN_SSIDS,
    
     [CCode (cname = "124")]
        NL80211_ATTR_MAX_SCHED_SCAN_IE_LEN,
    
     [CCode (cname = "125")]
        NL80211_ATTR_SCAN_SUPP_RATES,
    
     [CCode (cname = "126")]
        NL80211_ATTR_HIDDEN_SSID,
    
     [CCode (cname = "127")]
        NL80211_ATTR_IE_PROBE_RESP,
    
     [CCode (cname = "128")]
        NL80211_ATTR_IE_ASSOC_RESP,
    
     [CCode (cname = "129")]
        NL80211_ATTR_STA_WME,
    
     [CCode (cname = "130")]
        NL80211_ATTR_SUPPORT_AP_UAPSD,
    
     [CCode (cname = "131")]
        NL80211_ATTR_ROAM_SUPPORT,
    
     [CCode (cname = "132")]
        NL80211_ATTR_SCHED_SCAN_MATCH,
    
     [CCode (cname = "133")]
        NL80211_ATTR_MAX_MATCH_SETS,
    
     [CCode (cname = "134")]
        NL80211_ATTR_PMKSA_CANDIDATE,
    
     [CCode (cname = "135")]
        NL80211_ATTR_TX_NO_CCK_RATE,
    
     [CCode (cname = "136")]
        NL80211_ATTR_TDLS_ACTION,
    
     [CCode (cname = "137")]
        NL80211_ATTR_TDLS_DIALOG_TOKEN,
    
     [CCode (cname = "138")]
        NL80211_ATTR_TDLS_OPERATION,
    
     [CCode (cname = "139")]
        NL80211_ATTR_TDLS_SUPPORT,
    
     [CCode (cname = "140")]
        NL80211_ATTR_TDLS_EXTERNAL_SETUP,
    
     [CCode (cname = "141")]
        NL80211_ATTR_DEVICE_AP_SME,
    
     [CCode (cname = "142")]
        NL80211_ATTR_DONT_WAIT_FOR_ACK,
    
     [CCode (cname = "143")]
        NL80211_ATTR_FEATURE_FLAGS,
    
     [CCode (cname = "144")]
        NL80211_ATTR_PROBE_RESP_OFFLOAD,
    
     [CCode (cname = "145")]
        NL80211_ATTR_PROBE_RESP,
    
     [CCode (cname = "146")]
        NL80211_ATTR_DFS_REGION,
    
     [CCode (cname = "147")]
        NL80211_ATTR_DISABLE_HT,
    
     [CCode (cname = "148")]
        NL80211_ATTR_HT_CAPABILITY_MASK,
    
     [CCode (cname = "149")]
        NL80211_ATTR_NOACK_MAP,
    
     [CCode (cname = "150")]
        NL80211_ATTR_INACTIVITY_TIMEOUT,
    
     [CCode (cname = "151")]
        NL80211_ATTR_RX_SIGNAL_DBM,
    
     [CCode (cname = "152")]
        NL80211_ATTR_BG_SCAN_PERIOD,
    
     [CCode (cname = "153")]
        NL80211_ATTR_WDEV,
    
     [CCode (cname = "154")]
        NL80211_ATTR_USER_REG_HINT_TYPE,
    
     [CCode (cname = "155")]
        NL80211_ATTR_CONN_FAILED_REASON,
    
     [CCode (cname = "156")]
        NL80211_ATTR_AUTH_DATA,
    
     [CCode (cname = "157")]
        NL80211_ATTR_VHT_CAPABILITY,
    
     [CCode (cname = "158")]
        NL80211_ATTR_SCAN_FLAGS,
    
     [CCode (cname = "159")]
        NL80211_ATTR_CHANNEL_WIDTH,
    
     [CCode (cname = "160")]
        NL80211_ATTR_CENTER_FREQ1,
    
     [CCode (cname = "161")]
        NL80211_ATTR_CENTER_FREQ2,
    
     [CCode (cname = "162")]
        NL80211_ATTR_P2P_CTWINDOW,
    
     [CCode (cname = "163")]
        NL80211_ATTR_P2P_OPPPS,
    
     [CCode (cname = "164")]
        NL80211_ATTR_LOCAL_MESH_POWER_MODE,
    
     [CCode (cname = "165")]
        NL80211_ATTR_ACL_POLICY,
    
     [CCode (cname = "166")]
        NL80211_ATTR_MAC_ADDRS,
    
     [CCode (cname = "167")]
        NL80211_ATTR_MAC_ACL_MAX,
    
     [CCode (cname = "168")]
        NL80211_ATTR_RADAR_EVENT,
    
     [CCode (cname = "169")]
        NL80211_ATTR_EXT_CAPA,
    
     [CCode (cname = "170")]
        NL80211_ATTR_EXT_CAPA_MASK,
    
     [CCode (cname = "171")]
        NL80211_ATTR_STA_CAPABILITY,
    
     [CCode (cname = "172")]
        NL80211_ATTR_STA_EXT_CAPABILITY,
    
     [CCode (cname = "173")]
        NL80211_ATTR_PROTOCOL_FEATURES,
    
     [CCode (cname = "174")]
        NL80211_ATTR_SPLIT_WIPHY_DUMP,
    
     [CCode (cname = "175")]
        NL80211_ATTR_DISABLE_VHT,
    
     [CCode (cname = "176")]
        NL80211_ATTR_VHT_CAPABILITY_MASK,
    
     [CCode (cname = "177")]
        NL80211_ATTR_MDID,
    
     [CCode (cname = "178")]
        NL80211_ATTR_IE_RIC,
    
     [CCode (cname = "179")]
        NL80211_ATTR_CRIT_PROT_ID,
    
     [CCode (cname = "180")]
        NL80211_ATTR_MAX_CRIT_PROT_DURATION,
    
     [CCode (cname = "181")]
        NL80211_ATTR_PEER_AID,
    
     [CCode (cname = "182")]
        NL80211_ATTR_COALESCE_RULE,
    
     [CCode (cname = "183")]
        NL80211_ATTR_CH_SWITCH_COUNT,
    
     [CCode (cname = "184")]
        NL80211_ATTR_CH_SWITCH_BLOCK_TX,
    
     [CCode (cname = "185")]
        NL80211_ATTR_CSA_IES,
    
     [CCode (cname = "186")]
        NL80211_ATTR_CNTDWN_OFFS_BEACON,
    
     [CCode (cname = "187")]
        NL80211_ATTR_CNTDWN_OFFS_PRESP,
    
     [CCode (cname = "188")]
        NL80211_ATTR_RXMGMT_FLAGS,
    
     [CCode (cname = "189")]
        NL80211_ATTR_STA_SUPPORTED_CHANNELS,
    
     [CCode (cname = "190")]
        NL80211_ATTR_STA_SUPPORTED_OPER_CLASSES,
    
     [CCode (cname = "191")]
        NL80211_ATTR_HANDLE_DFS,
    
     [CCode (cname = "192")]
        NL80211_ATTR_SUPPORT_5_MHZ,
    
     [CCode (cname = "193")]
        NL80211_ATTR_SUPPORT_10_MHZ,
    
     [CCode (cname = "194")]
        NL80211_ATTR_OPMODE_NOTIF,
    
     [CCode (cname = "195")]
        NL80211_ATTR_VENDOR_ID,
    
     [CCode (cname = "196")]
        NL80211_ATTR_VENDOR_SUBCMD,
    
     [CCode (cname = "197")]
        NL80211_ATTR_VENDOR_DATA,
    
     [CCode (cname = "198")]
        NL80211_ATTR_VENDOR_EVENTS,
    
     [CCode (cname = "199")]
        NL80211_ATTR_QOS_MAP,
    
     [CCode (cname = "200")]
        NL80211_ATTR_MAC_HINT,
    
     [CCode (cname = "201")]
        NL80211_ATTR_WIPHY_FREQ_HINT,
    
     [CCode (cname = "202")]
        NL80211_ATTR_MAX_AP_ASSOC_STA,
    
     [CCode (cname = "203")]
        NL80211_ATTR_TDLS_PEER_CAPABILITY,
    
     [CCode (cname = "204")]
        NL80211_ATTR_SOCKET_OWNER,
    
     [CCode (cname = "205")]
        NL80211_ATTR_CSA_C_OFFSETS_TX,
    
     [CCode (cname = "206")]
        NL80211_ATTR_MAX_CSA_COUNTERS,
    
     [CCode (cname = "207")]
        NL80211_ATTR_TDLS_INITIATOR,
    
     [CCode (cname = "208")]
        NL80211_ATTR_USE_RRM,
    
     [CCode (cname = "209")]
        NL80211_ATTR_WIPHY_DYN_ACK,
    
     [CCode (cname = "210")]
        NL80211_ATTR_TSID,
    
     [CCode (cname = "211")]
        NL80211_ATTR_USER_PRIO,
    
     [CCode (cname = "212")]
        NL80211_ATTR_ADMITTED_TIME,
    
     [CCode (cname = "213")]
        NL80211_ATTR_SMPS_MODE,
    
     [CCode (cname = "214")]
        NL80211_ATTR_OPER_CLASS,
    
     [CCode (cname = "215")]
        NL80211_ATTR_MAC_MASK,
    
     [CCode (cname = "216")]
        NL80211_ATTR_WIPHY_SELF_MANAGED_REG,
    
     [CCode (cname = "217")]
        NL80211_ATTR_EXT_FEATURES,
    
     [CCode (cname = "218")]
        NL80211_ATTR_SURVEY_RADIO_STATS,
    
     [CCode (cname = "219")]
        NL80211_ATTR_NETNS_FD,
    
     [CCode (cname = "220")]
        NL80211_ATTR_SCHED_SCAN_DELAY,
    
     [CCode (cname = "221")]
        NL80211_ATTR_REG_INDOOR,
    
     [CCode (cname = "222")]
        NL80211_ATTR_MAX_NUM_SCHED_SCAN_PLANS,
    
     [CCode (cname = "223")]
        NL80211_ATTR_MAX_SCAN_PLAN_INTERVAL,
    
     [CCode (cname = "224")]
        NL80211_ATTR_MAX_SCAN_PLAN_ITERATIONS,
    
     [CCode (cname = "225")]
        NL80211_ATTR_SCHED_SCAN_PLANS,
    
     [CCode (cname = "226")]
        NL80211_ATTR_PBSS,
    
     [CCode (cname = "227")]
        NL80211_ATTR_BSS_SELECT,
    
     [CCode (cname = "228")]
        NL80211_ATTR_STA_SUPPORT_P2P_PS,
    
     [CCode (cname = "229")]
        NL80211_ATTR_PAD,
    
     [CCode (cname = "230")]
        NL80211_ATTR_IFTYPE_EXT_CAPA,
    
     [CCode (cname = "231")]
        NL80211_ATTR_MU_MIMO_GROUP_DATA,
    
     [CCode (cname = "232")]
        NL80211_ATTR_MU_MIMO_FOLLOW_MAC_ADDR,
    
     [CCode (cname = "233")]
        NL80211_ATTR_SCAN_START_TIME_TSF,
    
     [CCode (cname = "234")]
        NL80211_ATTR_SCAN_START_TIME_TSF_BSSID,
    
     [CCode (cname = "235")]
        NL80211_ATTR_MEASUREMENT_DURATION,
    
     [CCode (cname = "236")]
        NL80211_ATTR_MEASUREMENT_DURATION_MANDATORY,
    
     [CCode (cname = "237")]
        NL80211_ATTR_MESH_PEER_AID,
    
     [CCode (cname = "238")]
        NL80211_ATTR_NAN_MASTER_PREF,
    
     [CCode (cname = "239")]
        NL80211_ATTR_BANDS,
    
     [CCode (cname = "240")]
        NL80211_ATTR_NAN_FUNC,
    
     [CCode (cname = "241")]
        NL80211_ATTR_NAN_MATCH,
    
     [CCode (cname = "242")]
        NL80211_ATTR_FILS_KEK,
    
     [CCode (cname = "243")]
        NL80211_ATTR_FILS_NONCES,
    
     [CCode (cname = "244")]
        NL80211_ATTR_MULTICAST_TO_UNICAST_ENABLED,
    
     [CCode (cname = "245")]
        NL80211_ATTR_BSSID,
    
     [CCode (cname = "246")]
        NL80211_ATTR_SCHED_SCAN_RELATIVE_RSSI,
    
     [CCode (cname = "247")]
        NL80211_ATTR_SCHED_SCAN_RSSI_ADJUST,
    
     [CCode (cname = "248")]
        NL80211_ATTR_TIMEOUT_REASON,
    
     [CCode (cname = "249")]
        NL80211_ATTR_FILS_ERP_USERNAME,
    
     [CCode (cname = "250")]
        NL80211_ATTR_FILS_ERP_REALM,
    
     [CCode (cname = "251")]
        NL80211_ATTR_FILS_ERP_NEXT_SEQ_NUM,
    
     [CCode (cname = "252")]
        NL80211_ATTR_FILS_ERP_RRK,
    
     [CCode (cname = "253")]
        NL80211_ATTR_FILS_CACHE_ID,
    
     [CCode (cname = "254")]
        NL80211_ATTR_PMK,
    
     [CCode (cname = "255")]
        NL80211_ATTR_SCHED_SCAN_MULTI,
    
     [CCode (cname = "256")]
        NL80211_ATTR_SCHED_SCAN_MAX_REQS,
    
     [CCode (cname = "257")]
        NL80211_ATTR_WANT_1X_4WAY_HS,
    
     [CCode (cname = "258")]
        NL80211_ATTR_PMKR0_NAME,
    
     [CCode (cname = "259")]
        NL80211_ATTR_PORT_AUTHORIZED,
    
     [CCode (cname = "260")]
        NL80211_ATTR_EXTERNAL_AUTH_ACTION,
    
     [CCode (cname = "261")]
        NL80211_ATTR_EXTERNAL_AUTH_SUPPORT,
    
     [CCode (cname = "262")]
        NL80211_ATTR_NSS,
    
     [CCode (cname = "263")]
        NL80211_ATTR_ACK_SIGNAL,
    
     [CCode (cname = "264")]
        NL80211_ATTR_CONTROL_PORT_OVER_NL80211,
    
     [CCode (cname = "265")]
        NL80211_ATTR_TXQ_STATS,
    
     [CCode (cname = "266")]
        NL80211_ATTR_TXQ_LIMIT,
    
     [CCode (cname = "267")]
        NL80211_ATTR_TXQ_MEMORY_LIMIT,
    
     [CCode (cname = "268")]
        NL80211_ATTR_TXQ_QUANTUM,
    
     [CCode (cname = "269")]
        NL80211_ATTR_HE_CAPABILITY,
    
     [CCode (cname = "270")]
        NL80211_ATTR_FTM_RESPONDER,
    
     [CCode (cname = "271")]
        NL80211_ATTR_FTM_RESPONDER_STATS,
    
     [CCode (cname = "272")]
        NL80211_ATTR_TIMEOUT,
    
     [CCode (cname = "273")]
        NL80211_ATTR_PEER_MEASUREMENTS,
    
     [CCode (cname = "274")]
        NL80211_ATTR_AIRTIME_WEIGHT,
    
     [CCode (cname = "275")]
        NL80211_ATTR_STA_TX_POWER_SETTING,
    
     [CCode (cname = "276")]
        NL80211_ATTR_STA_TX_POWER,
    
     [CCode (cname = "277")]
        NL80211_ATTR_SAE_PASSWORD,
    
     [CCode (cname = "278")]
        NL80211_ATTR_TWT_RESPONDER,
    
     [CCode (cname = "279")]
        NL80211_ATTR_HE_OBSS_PD,
    
     [CCode (cname = "280")]
        NL80211_ATTR_WIPHY_EDMG_CHANNELS,
    
     [CCode (cname = "281")]
        NL80211_ATTR_WIPHY_EDMG_BW_CONFIG,
    
     [CCode (cname = "282")]
        NL80211_ATTR_VLAN_ID,
    
     [CCode (cname = "283")]
        NL80211_ATTR_HE_BSS_COLOR,
    
     [CCode (cname = "284")]
        NL80211_ATTR_IFTYPE_AKM_SUITES,
    
     [CCode (cname = "285")]
        NL80211_ATTR_TID_CONFIG,
    
     [CCode (cname = "286")]
        NL80211_ATTR_CONTROL_PORT_NO_PREAUTH,
    
     [CCode (cname = "287")]
        NL80211_ATTR_PMK_LIFETIME,
    
     [CCode (cname = "288")]
        NL80211_ATTR_PMK_REAUTH_THRESHOLD,
    
     [CCode (cname = "289")]
        NL80211_ATTR_RECEIVE_MULTICAST,
    
     [CCode (cname = "290")]
        NL80211_ATTR_WIPHY_FREQ_OFFSET,
    
     [CCode (cname = "291")]
        NL80211_ATTR_CENTER_FREQ1_OFFSET,
    
     [CCode (cname = "292")]
        NL80211_ATTR_SCAN_FREQ_KHZ,
    
     [CCode (cname = "293")]
        NL80211_ATTR_HE_6GHZ_CAPABILITY,
    
     [CCode (cname = "294")]
        NL80211_ATTR_FILS_DISCOVERY,
    
     [CCode (cname = "295")]
        NL80211_ATTR_UNSOL_BCAST_PROBE_RESP,
    
     [CCode (cname = "296")]
        NL80211_ATTR_S1G_CAPABILITY,
    
     [CCode (cname = "297")]
        NL80211_ATTR_S1G_CAPABILITY_MASK,
    
     [CCode (cname = "298")]
        NL80211_ATTR_SAE_PWE,
    
     [CCode (cname = "299")]
        NL80211_ATTR_RECONNECT_REQUESTED,
    
     [CCode (cname = "300")]
        NL80211_ATTR_SAR_SPEC,
    
     [CCode (cname = "301")]
        NL80211_ATTR_DISABLE_HE,
    
     [CCode (cname = "302")]
        NL80211_ATTR_OBSS_COLOR_BITMAP,
    
     [CCode (cname = "303")]
        NL80211_ATTR_COLOR_CHANGE_COUNT,
    
     [CCode (cname = "304")]
        NL80211_ATTR_COLOR_CHANGE_COLOR,
    
     [CCode (cname = "305")]
        NL80211_ATTR_COLOR_CHANGE_ELEMS,
    
     [CCode (cname = "306")]
        NL80211_ATTR_MBSSID_CONFIG,
    
     [CCode (cname = "307")]
        NL80211_ATTR_MBSSID_ELEMS,
    
     [CCode (cname = "308")]
        NL80211_ATTR_RADAR_BACKGROUND,
    
     [CCode (cname = "309")]
        NL80211_ATTR_AP_SETTINGS_FLAGS,
    
     [CCode (cname = "310")]
        NL80211_ATTR_EHT_CAPABILITY,
    
     [CCode (cname = "311")]
        NL80211_ATTR_DISABLE_EHT,
    
     [CCode (cname = "312")]
        NL80211_ATTR_MLO_LINKS,
    
     [CCode (cname = "313")]
        NL80211_ATTR_MLO_LINK_ID,
    
     [CCode (cname = "314")]
        NL80211_ATTR_MLD_ADDR,
    
     [CCode (cname = "315")]
        NL80211_ATTR_MLO_SUPPORT,
    
     [CCode (cname = "316")]
        NL80211_ATTR_MAX_NUM_AKM_SUITES,
    
     [CCode (cname = "317")]
        NL80211_ATTR_EML_CAPABILITY,
    
     [CCode (cname = "318")]
        NL80211_ATTR_MLD_CAPA_AND_OPS,
    
     [CCode (cname = "319")]
        NL80211_ATTR_TX_HW_TIMESTAMP,
    
     [CCode (cname = "320")]
        NL80211_ATTR_RX_HW_TIMESTAMP,
    
     [CCode (cname = "321")]
        NL80211_ATTR_TD_BITMAP,
    
     [CCode (cname = "322")]
        NL80211_ATTR_PUNCT_BITMAP,
    
     [CCode (cname = "323")]
        NL80211_ATTR_MAX_HW_TIMESTAMP_PEERS,
    
     [CCode (cname = "324")]
        NL80211_ATTR_HW_TIMESTAMP_ENABLED,
    
     [CCode (cname = "325")]
        NL80211_ATTR_EMA_RNR_ELEMS,
    
     [CCode (cname = "326")]
        NL80211_ATTR_MLO_LINK_DISABLED,
    
     [CCode (cname = "327")]
        __NL80211_ATTR_AFTER_LAST,
    
     [CCode (cname = "327")]
        NUM_NL80211_ATTR,
    
     [CCode (cname = "326")]
        NL80211_ATTR_MAX
    }
    
    [CCode (has_type_id = false, cname = "int")]
    enum Command {
        /* don't change the order or add anything inbetween, this is ABI! */
        [CCode (cname = "0")]
        NL80211_CMD_UNSPEC,
    
     [CCode (cname = "1")]
       NL80211_CMD_GET_WIPHY,		/* can dump */
    
     [CCode (cname = "2")]
       NL80211_CMD_SET_WIPHY,
    
     [CCode (cname = "3")]
       NL80211_CMD_NEW_WIPHY,
    
     [CCode (cname = "4")]
       NL80211_CMD_DEL_WIPHY,
    
     [CCode (cname = "5")]
       NL80211_CMD_GET_INTERFACE,	/* can dump */
    
     [CCode (cname = "6")]
       NL80211_CMD_SET_INTERFACE,
    
     [CCode (cname = "7")]
       NL80211_CMD_NEW_INTERFACE,
    
     [CCode (cname = "8")]
       NL80211_CMD_DEL_INTERFACE,
    
     [CCode (cname = "9")]
       NL80211_CMD_GET_KEY,
    
     [CCode (cname = "10")]
       NL80211_CMD_SET_KEY,
    
     [CCode (cname = "11")]
       NL80211_CMD_NEW_KEY,
    
     [CCode (cname = "12")]
       NL80211_CMD_DEL_KEY,
    
     [CCode (cname = "13")]
       NL80211_CMD_GET_BEACON,
    
     [CCode (cname = "14")]
       NL80211_CMD_SET_BEACON,
    
     [CCode (cname = "15")]
       NL80211_CMD_START_AP,
    
     [CCode (cname = "16")]
       NL80211_CMD_STOP_AP,
    
     [CCode (cname = "17")]
       NL80211_CMD_GET_STATION,
    
     [CCode (cname = "18")]
       NL80211_CMD_SET_STATION,
    
     [CCode (cname = "19")]
       NL80211_CMD_NEW_STATION,
    
     [CCode (cname = "20")]
       NL80211_CMD_DEL_STATION,
    
     [CCode (cname = "21")]
       NL80211_CMD_GET_MPATH,
    
     [CCode (cname = "22")]
       NL80211_CMD_SET_MPATH,
    
     [CCode (cname = "23")]
       NL80211_CMD_NEW_MPATH,
    
     [CCode (cname = "24")]
       NL80211_CMD_DEL_MPATH,
    
     [CCode (cname = "25")]
       NL80211_CMD_SET_BSS,
    
     [CCode (cname = "26")]
       NL80211_CMD_SET_REG,
    
     [CCode (cname = "27")]
       NL80211_CMD_REQ_SET_REG,
    
     [CCode (cname = "28")]
       NL80211_CMD_GET_MESH_CONFIG,
    
     [CCode (cname = "29")]
       NL80211_CMD_SET_MESH_CONFIG,
    
     [CCode (cname = "30")]
       NL80211_CMD_SET_MGMT_EXTRA_IE /* reserved; not used */,
    
     [CCode (cname = "31")]
       NL80211_CMD_GET_REG,
    
     [CCode (cname = "32")]
       NL80211_CMD_GET_SCAN,
    
     [CCode (cname = "33")]
       NL80211_CMD_TRIGGER_SCAN,
    
     [CCode (cname = "34")]
       NL80211_CMD_NEW_SCAN_RESULTS,
    
     [CCode (cname = "35")]
       NL80211_CMD_SCAN_ABORTED,
    
     [CCode (cname = "36")]
       NL80211_CMD_REG_CHANGE,
    
     [CCode (cname = "37")]
       NL80211_CMD_AUTHENTICATE,
    
     [CCode (cname = "38")]
       NL80211_CMD_ASSOCIATE,
    
     [CCode (cname = "39")]
       NL80211_CMD_DEAUTHENTICATE,
    
     [CCode (cname = "40")]
       NL80211_CMD_DISASSOCIATE,
    
     [CCode (cname = "41")]
       NL80211_CMD_MICHAEL_MIC_FAILURE,
    
     [CCode (cname = "42")]
       NL80211_CMD_REG_BEACON_HINT,
    
     [CCode (cname = "43")]
       NL80211_CMD_JOIN_IBSS,
    
     [CCode (cname = "44")]
       NL80211_CMD_LEAVE_IBSS,
    
     [CCode (cname = "45")]
       NL80211_CMD_TESTMODE,
    
     [CCode (cname = "46")]
       NL80211_CMD_CONNECT,
    
     [CCode (cname = "47")]
       NL80211_CMD_ROAM,
    
     [CCode (cname = "48")]
       NL80211_CMD_DISCONNECT,
    
     [CCode (cname = "49")]
       NL80211_CMD_SET_WIPHY_NETNS,
    
     [CCode (cname = "50")]
       NL80211_CMD_GET_SURVEY,
    
     [CCode (cname = "51")]
       NL80211_CMD_NEW_SURVEY_RESULTS,
    
     [CCode (cname = "52")]
       NL80211_CMD_SET_PMKSA,
    
     [CCode (cname = "53")]
       NL80211_CMD_DEL_PMKSA,
    
     [CCode (cname = "54")]
       NL80211_CMD_FLUSH_PMKSA,
    
     [CCode (cname = "55")]
       NL80211_CMD_REMAIN_ON_CHANNEL,
    
     [CCode (cname = "56")]
       NL80211_CMD_CANCEL_REMAIN_ON_CHANNEL,
    
     [CCode (cname = "57")]
       NL80211_CMD_SET_TX_BITRATE_MASK,
    
     [CCode (cname = "58")]
       NL80211_CMD_REGISTER_FRAME,
    
     [CCode (cname = "59")]
       NL80211_CMD_FRAME,
    
     [CCode (cname = "60")]
       NL80211_CMD_FRAME_TX_STATUS,
    
     [CCode (cname = "61")]
       NL80211_CMD_SET_POWER_SAVE,
    
     [CCode (cname = "62")]
       NL80211_CMD_GET_POWER_SAVE,
    
     [CCode (cname = "63")]
       NL80211_CMD_SET_CQM,
    
     [CCode (cname = "64")]
       NL80211_CMD_NOTIFY_CQM,
    
     [CCode (cname = "65")]
       NL80211_CMD_SET_CHANNEL,
    
     [CCode (cname = "66")]
       NL80211_CMD_SET_WDS_PEER,
    
     [CCode (cname = "67")]
       NL80211_CMD_FRAME_WAIT_CANCEL,
    
     [CCode (cname = "68")]
       NL80211_CMD_JOIN_MESH,
    
     [CCode (cname = "69")]
       NL80211_CMD_LEAVE_MESH,
    
     [CCode (cname = "70")]
       NL80211_CMD_UNPROT_DEAUTHENTICATE,
    
     [CCode (cname = "71")]
       NL80211_CMD_UNPROT_DISASSOCIATE,
    
     [CCode (cname = "72")]
       NL80211_CMD_NEW_PEER_CANDIDATE,
    
     [CCode (cname = "73")]
       NL80211_CMD_GET_WOWLAN,
    
     [CCode (cname = "74")]
       NL80211_CMD_SET_WOWLAN,
    
     [CCode (cname = "75")]
       NL80211_CMD_START_SCHED_SCAN,
    
     [CCode (cname = "76")]
       NL80211_CMD_STOP_SCHED_SCAN,
    
     [CCode (cname = "77")]
       NL80211_CMD_SCHED_SCAN_RESULTS,
    
     [CCode (cname = "78")]
       NL80211_CMD_SCHED_SCAN_STOPPED,
    
     [CCode (cname = "79")]
       NL80211_CMD_SET_REKEY_OFFLOAD,
    
     [CCode (cname = "80")]
       NL80211_CMD_PMKSA_CANDIDATE,
    
     [CCode (cname = "81")]
       NL80211_CMD_TDLS_OPER,
    
     [CCode (cname = "82")]
       NL80211_CMD_TDLS_MGMT,
    
     [CCode (cname = "83")]
       NL80211_CMD_UNEXPECTED_FRAME,
    
     [CCode (cname = "84")]
       NL80211_CMD_PROBE_CLIENT,
    
     [CCode (cname = "85")]
       NL80211_CMD_REGISTER_BEACONS,
    
     [CCode (cname = "86")]
       NL80211_CMD_UNEXPECTED_4ADDR_FRAME,
    
     [CCode (cname = "87")]
       NL80211_CMD_SET_NOACK_MAP,
    
     [CCode (cname = "88")]
       NL80211_CMD_CH_SWITCH_NOTIFY,
    
     [CCode (cname = "89")]
       NL80211_CMD_START_P2P_DEVICE,
    
     [CCode (cname = "90")]
       NL80211_CMD_STOP_P2P_DEVICE,
    
     [CCode (cname = "91")]
       NL80211_CMD_CONN_FAILED,
    
     [CCode (cname = "92")]
       NL80211_CMD_SET_MCAST_RATE,
    
     [CCode (cname = "93")]
       NL80211_CMD_SET_MAC_ACL,
    
     [CCode (cname = "94")]
       NL80211_CMD_RADAR_DETECT,
    
     [CCode (cname = "95")]
       NL80211_CMD_GET_PROTOCOL_FEATURES,
    
     [CCode (cname = "96")]
       NL80211_CMD_UPDATE_FT_IES,
    
     [CCode (cname = "97")]
       NL80211_CMD_FT_EVENT,
    
     [CCode (cname = "98")]
       NL80211_CMD_CRIT_PROTOCOL_START,
    
     [CCode (cname = "99")]
       NL80211_CMD_CRIT_PROTOCOL_STOP,
    
     [CCode (cname = "100")]
       NL80211_CMD_GET_COALESCE,
    
     [CCode (cname = "101")]
       NL80211_CMD_SET_COALESCE,
    
     [CCode (cname = "102")]
       NL80211_CMD_CHANNEL_SWITCH,
    
     [CCode (cname = "103")]
       NL80211_CMD_VENDOR,
    
     [CCode (cname = "104")]
       NL80211_CMD_SET_QOS_MAP,
    
     [CCode (cname = "105")]
       NL80211_CMD_ADD_TX_TS,
    
     [CCode (cname = "106")]
       NL80211_CMD_DEL_TX_TS,
    
     [CCode (cname = "107")]
       NL80211_CMD_GET_MPP,
    
     [CCode (cname = "108")]
       NL80211_CMD_JOIN_OCB,
    
     [CCode (cname = "109")]
       NL80211_CMD_LEAVE_OCB,
    
     [CCode (cname = "110")]
       NL80211_CMD_CH_SWITCH_STARTED_NOTIFY,
    
     [CCode (cname = "111")]
       NL80211_CMD_TDLS_CHANNEL_SWITCH,
    
     [CCode (cname = "112")]
       NL80211_CMD_TDLS_CANCEL_CHANNEL_SWITCH,
    
     [CCode (cname = "113")]
       NL80211_CMD_WIPHY_REG_CHANGE,
    
     [CCode (cname = "114")]
       NL80211_CMD_ABORT_SCAN,
    
     [CCode (cname = "115")]
       __NL80211_CMD_AFTER_LAST,
    
     [CCode (cname = "114")]
       NL80211_CMD_MAX 
    
    }

    [CCode (has_type_id = false, cname = "int")]
    enum STAAttribute {
        [CCode (cname = "0")]
        __NL80211_STA_INFO_INVALID,

        [CCode (cname = "1")]
        NL80211_STA_INFO_INACTIVE_TIME,

        [CCode (cname = "2")]
        NL80211_STA_INFO_RX_BYTES,

        [CCode (cname = "3")]
        NL80211_STA_INFO_TX_BYTES,

        [CCode (cname = "4")]
        NL80211_STA_INFO_LLID,

        [CCode (cname = "5")]
        NL80211_STA_INFO_PLID,

        [CCode (cname = "6")]
        NL80211_STA_INFO_PLINK_STATE,

        [CCode (cname = "7")]
        NL80211_STA_INFO_SIGNAL,

        [CCode (cname = "8")]
        NL80211_STA_INFO_TX_BITRATE,

        [CCode (cname = "9")]
        NL80211_STA_INFO_RX_PACKETS,

        [CCode (cname = "10")]
        NL80211_STA_INFO_TX_PACKETS,

        [CCode (cname = "11")]
        NL80211_STA_INFO_TX_RETRIES,

        [CCode (cname = "12")]
        NL80211_STA_INFO_TX_FAILED,

        [CCode (cname = "13")]
        NL80211_STA_INFO_SIGNAL_AVG,

        [CCode (cname = "14")]
        NL80211_STA_INFO_RX_BITRATE,

        [CCode (cname = "15")]
        NL80211_STA_INFO_BSS_PARAM,

        [CCode (cname = "16")]
        NL80211_STA_INFO_CONNECTED_TIME,

        [CCode (cname = "17")]
        NL80211_STA_INFO_STA_FLAGS,

        [CCode (cname = "18")]
        NL80211_STA_INFO_BEACON_LOSS,

        [CCode (cname = "19")]
        NL80211_STA_INFO_T_OFFSET,

        [CCode (cname = "20")]
        NL80211_STA_INFO_LOCAL_PM,

        [CCode (cname = "21")]
        NL80211_STA_INFO_PEER_PM,

        [CCode (cname = "22")]
        NL80211_STA_INFO_NONPEER_PM,

        [CCode (cname = "23")]
        NL80211_STA_INFO_RX_BYTES64,

        [CCode (cname = "24")]
        NL80211_STA_INFO_TX_BYTES64,

        [CCode (cname = "25")]
        NL80211_STA_INFO_CHAIN_SIGNAL,

        [CCode (cname = "26")]
        NL80211_STA_INFO_CHAIN_SIGNAL_AVG,

        [CCode (cname = "27")]
        NL80211_STA_INFO_EXPECTED_THROUGHPUT,

        [CCode (cname = "28")]
        NL80211_STA_INFO_RX_DROP_MISC,

        [CCode (cname = "29")]
        NL80211_STA_INFO_BEACON_RX,

        [CCode (cname = "30")]
        NL80211_STA_INFO_BEACON_SIGNAL_AVG,

        [CCode (cname = "31")]
        NL80211_STA_INFO_TID_STATS,

        [CCode (cname = "32")]
        NL80211_STA_INFO_MAX
    }

    [CCode (has_type_id = false, cname = "int")]
    enum BSSAttribute {
        [CCode (cname = "0")]
        __NL80211_BSS_INVALID,

        [CCode (cname = "1")]
        NL80211_BSS_BSSID,

        [CCode (cname = "2")]
        NL80211_BSS_FREQUENCY,

        [CCode (cname = "3")]
        NL80211_BSS_TSF,

        [CCode (cname = "4")]
        NL80211_BSS_BEACON_INTERVAL,

        [CCode (cname = "5")]
        NL80211_BSS_CAPABILITY,

        [CCode (cname = "6")]
        NL80211_BSS_INFORMATION_ELEMENTS,

        [CCode (cname = "7")]
        NL80211_BSS_SIGNAL_MBM,

        [CCode (cname = "8")]
        NL80211_BSS_SIGNAL_UNSPEC,

        [CCode (cname = "9")]
        NL80211_BSS_STATUS,

        [CCode (cname = "10")]
        NL80211_BSS_SEEN_MS_AGO,

        [CCode (cname = "11")]
        NL80211_BSS_BEACON_IES,

        [CCode (cname = "12")]
        NL80211_BSS_CHAN_WIDTH,

        [CCode (cname = "13")]
        NL80211_BSS_BEACON_TSF,

        [CCode (cname = "14")]
        NL80211_BSS_PRESP_DATA,

        [CCode (cname = "15")]
        NL80211_BSS_MAX
    }

    [CCode (has_type_id = false, cname = "int")]
    public enum BSSStatus {
        [CCode (cname = "0")]
        NL80211_BSS_STATUS_AUTHENTICATED,

        [CCode (cname = "1")]
        NL80211_BSS_STATUS_ASSOCIATED,

        [CCode (cname = "2")]
        NL80211_BSS_STATUS_IBSS_JOINED,
    }

    [CCode (has_type_id = false, cname = "int")]
    public enum InterfaceType {
      [CCode (cname = "0")]
      NL80211_IFTYPE_UNSPECIFIED,

      [CCode (cname = "1")]
      NL80211_IFTYPE_ADHOC,

      [CCode (cname = "2")]
      NL80211_IFTYPE_STATION,

      [CCode (cname = "3")]
      NL80211_IFTYPE_AP,

      [CCode (cname = "4")]
      NL80211_IFTYPE_AP_VLAN,

      [CCode (cname = "5")]
      NL80211_IFTYPE_WDS,

      [CCode (cname = "6")]
      NL80211_IFTYPE_MONITOR,

      [CCode (cname = "7")]
      NL80211_IFTYPE_MESH_POINT,

      [CCode (cname = "8")]
      NL80211_IFTYPE_P2P_CLIENT,

      [CCode (cname = "9")]
      NL80211_IFTYPE_P2P_GO,

      [CCode (cname = "10")]
      NL80211_IFTYPE_P2P_DEVICE,

      [CCode (cname = "11")]
      NL80211_IFTYPE_OCB,

      [CCode (cname = "12")]
      NL80211_IFTYPE_NAN,

      [CCode (cname = "13")]
      NUM_NL80211_IFTYPES,

      [CCode (cname = "12")]
      NL80211_IFTYPE_MAX
   }

   [CCode (has_type_id = false, cname = "int")]
   enum InterfaceCombinationAttribute {
      [CCode (cname = "0")]
      NL80211_IFACE_COMB_UNSPEC,

      [CCode (cname = "1")]
      NL80211_IFACE_COMB_LIMITS,

      [CCode (cname = "2")]
      NL80211_IFACE_COMB_MAXNUM,

      [CCode (cname = "3")]
      NL80211_IFACE_COMB_STA_AP_BI_MATCH,

      [CCode (cname = "4")]
      NL80211_IFACE_COMB_NUM_CHANNELS,

      [CCode (cname = "5")]
      NL80211_IFACE_COMB_RADAR_DETECT_WIDTHS,

      [CCode (cname = "6")]
      NL80211_IFACE_COMB_RADAR_DETECT_REGIONS,

      [CCode (cname = "7")]
      NUM_NL80211_IFACE_COMB,

      [CCode (cname = "6")]
      MAX_NL80211_IFACE_COMB

   }

   [CCode (has_type_id = false, cname = "int")]
   enum InterfaceCombinationLimitAttribute {
      [CCode (cname = "0")]
      NL80211_IFACE_LIMIT_UNSPEC,
      [CCode (cname = "1")]
      NL80211_IFACE_LIMIT_MAX,
      [CCode (cname = "2")]
      NL80211_IFACE_LIMIT_TYPES,
   
      /* keep last */
      [CCode (cname = "3")]
      NUM_NL80211_IFACE_LIMIT,
      [CCode (cname = "2")]
      MAX_NL80211_IFACE_LIMIT
   }

   [CCode (has_type_id = false, cname = "int")]
   enum PowerSaveState {
      [CCode (cname = "0")]
      NL80211_PS_DISABLED,
      [CCode (cname = "1")]
      NL80211_PS_ENABLED,
   }

 }
 