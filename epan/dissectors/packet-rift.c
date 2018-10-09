#include "config.h"

#include <epan/packet.h>

#define UDP_PORT_RIFT 20001 /* TODO change this */

static int proto_rift = -1;

static int
dissect_rift(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_)
{
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "rift");
    col_clear(pinfo->cinfo, COL_INFO);
    return tvb_captured_length(tvb);
}

void
proto_register_rift(void)
{
    proto_rift = proto_register_protocol("Routing In Fat Trees", "RIFT", "rift");
}

void
proto_reg_handoff_rift(void)
{
    static dissector_handle_t rift_handle;

    rift_handle = create_dissector_handle(dissect_rift, proto_rift);
    dissector_add_uint("udp.port", UDP_PORT_RIFT, rift_handle);
}
