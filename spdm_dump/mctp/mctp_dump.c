/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/spdm-dump/blob/main/LICENSE.md
 **/

#include "spdm_dump.h"

void *m_reassembly_data_buffer;
uint32_t data_buffer_size = 0;

dispatch_table_entry_t m_mctp_dispatch[] = {
    { MCTP_MESSAGE_TYPE_MCTP_CONTROL, "MctpControl", dump_mctp_control_message },
    { MCTP_MESSAGE_TYPE_PLDM, "PLDM", dump_pldm_message },
    { MCTP_MESSAGE_TYPE_NCSI_CONTROL, "NCSI", NULL },
    { MCTP_MESSAGE_TYPE_ETHERNET, "Ethernet", NULL },
    { MCTP_MESSAGE_TYPE_NVME_MANAGEMENT, "NVMe", NULL },
    { MCTP_MESSAGE_TYPE_SPDM, "SPDM", dump_spdm_message },
    { MCTP_MESSAGE_TYPE_SECURED_MCTP, "SecuredSPDM",
      dump_secured_spdm_message },
    { MCTP_MESSAGE_TYPE_VENDOR_DEFINED_PCI, "VendorDefinedPci", NULL },
    { MCTP_MESSAGE_TYPE_VENDOR_DEFINED_IANA, "VendorDefinedIana", NULL },
};

value_string_entry_t m_mctp_transport_header_flag_string_table[] = {
        {MCTP_HDR_FLAG_TO,  "TO"},
        {MCTP_HDR_FLAG_SOM, "SOM"},
        {MCTP_HDR_FLAG_EOM, "EOM"},
};

value_string_entry_t m_mctp_control_command_code_string_table[] = {
        {MCTP_CTRL_CMD_RESERVED,                   "RESERVED"},
        {MCTP_CTRL_CMD_SET_ENDPOINT_ID,            "SetEID"},
        {MCTP_CTRL_CMD_GET_ENDPOINT_ID,            "GetEID"},
        {MCTP_CTRL_CMD_GET_ENDPOINT_UUID,          "GetUUID"},
        {MCTP_CTRL_CMD_GET_VERSION_SUPPORT,        "GetVersionSupport"},
        {MCTP_CTRL_CMD_GET_MESSAGE_TYPE_SUPPORT,   "GetMsgTypeSupport"},
        {MCTP_CTRL_CMD_GET_VENDOR_MESSAGE_SUPPORT, "GetVenderMsgSupport"},
        {MCTP_CTRL_CMD_RESOLVE_ENDPOINT_ID,        "ResolveEID"},
        {MCTP_CTRL_CMD_ALLOCATE_ENDPOINT_IDS,      "AllocateEIDs"},
        {MCTP_CTRL_CMD_ROUTING_INFO_UPDATE,        "RoutingInfoUpdate"},
        {MCTP_CTRL_CMD_GET_ROUTING_TABLE_ENTRIES,  "GetRoutingTableEntries"},
        {MCTP_CTRL_CMD_PREPARE_ENDPOINT_DISCOVERY, "PrepareEndpointDiscovery"},
        {MCTP_CTRL_CMD_ENDPOINT_DISCOVERY,         "EndpointDiscovery"},
        {MCTP_CTRL_CMD_DISCOVERY_NOTIFY,           "DiscoveryNotify"},
        {MCTP_CTRL_CMD_GET_NETWORK_ID,             "GetNetworkID"},
        {MCTP_CTRL_CMD_QUERY_HOP,                  "QueryHop"},
        {MCTP_CTRL_CMD_RESOLVE_UUID,               "ResolveUUID"},
        {MCTP_CTRL_CMD_QUERY_RATE_LIMIT,           "QueryRateLimit"},
        {MCTP_CTRL_CMD_REQUEST_TX_RATE_LIMIT,      "RequestTXRateLimit"},
        {MCTP_CTRL_CMD_UPDATE_RATE_LIMIT,          "UpdateRateLimit"},
        {MCTP_CTRL_CMD_QUERY_SUPPORTED_INTERFACES, "QuerySupportedInterfaces"},
        {MCTP_CTRL_CMD_MAX,                        "INVALID"},
};

void dump_mctp_control_message(const void *buffer, size_t buffer_size) {
    const mctp_control_message_header_t *ctrl_hdr;
    const mctp_control_message_response_header_t *ctrl_response_hdr;
    bool is_req;

    if (buffer_size < sizeof(mctp_control_message_header_t)) {
        printf("\n");
        return;
    }

    ctrl_hdr = buffer;
    is_req = ((ctrl_hdr->rq_dgram_inst & MCTP_CTRL_HDR_FLAG_REQUEST) == MCTP_CTRL_HDR_FLAG_REQUEST);

    if (!is_req) {
        if (buffer_size < sizeof(mctp_control_message_response_header_t)) {
            printf("\n");
            return;
        }
        ctrl_response_hdr = buffer;
    }

    printf("%s CONTROL(0x%02x, 0x%02x) ",
           is_req ? "REQ" : "RSP",
           ctrl_hdr->rq_dgram_inst & MCTP_CTRL_HDR_INSTANCE_ID_MASK,
           ctrl_hdr->command_code);

    dump_entry_value(m_mctp_control_command_code_string_table,
                     LIBSPDM_ARRAY_SIZE(m_mctp_control_command_code_string_table), ctrl_hdr->command_code);

    printf(" (");
    if (!is_req) {
        printf("0x%02x", ctrl_response_hdr->completion_code);
    }
    printf(")\n");
}

void dump_mctp_message(const void *buffer, size_t buffer_size)
{
    mctp_message_header_t *mctp_message_header;
    size_t header_size;

    header_size = sizeof(mctp_message_header_t);
    if (buffer_size < header_size) {
        printf("\n");
        return;
    }
    mctp_message_header = (mctp_message_header_t *)((uint8_t *)buffer);

    printf("MCTP(%d) ", mctp_message_header->message_type);

    if (m_param_dump_vendor_app ||
        (mctp_message_header->message_type == MCTP_MESSAGE_TYPE_SPDM) ||
        (mctp_message_header->message_type ==
         MCTP_MESSAGE_TYPE_SECURED_MCTP)) {
        dump_dispatch_message(m_mctp_dispatch,
                              LIBSPDM_ARRAY_SIZE(m_mctp_dispatch),
                              mctp_message_header->message_type,
                              (uint8_t *)buffer + header_size,
                              buffer_size - header_size);

        if (m_param_dump_hex &&
            (mctp_message_header->message_type !=
             MCTP_MESSAGE_TYPE_SPDM) &&
            (mctp_message_header->message_type !=
             MCTP_MESSAGE_TYPE_SECURED_MCTP)) {
            printf("  MCTP message:\n");
            dump_hex(buffer, buffer_size);
        }
    } else {
        printf("\n");
    }
}

void dump_mctp_packet(const void *buffer, size_t buffer_size) {
    size_t header_size;
    mctp_header_t *hdr;

    header_size = sizeof(mctp_header_t);
    if (buffer_size < header_size) {
        return;
    }

    hdr = (mctp_header_t *) buffer;

    // buffer contains entire message and can be directly processed
    if ((hdr->message_tag & (MCTP_HDR_FLAG_SOM | MCTP_HDR_FLAG_EOM)) == (MCTP_HDR_FLAG_SOM | MCTP_HDR_FLAG_EOM)) {
        dump_mctp_message((uint8_t *) buffer + header_size,
                          buffer_size - header_size);
        return;
    }

    // message is fragmented, need to reassemble the message before processing the buffer

    size_t starting_offset = header_size;
    if (hdr->message_tag & MCTP_HDR_FLAG_SOM) {
        m_reassembly_data_buffer = (void *) malloc(get_max_packet_length());
    }
    if (m_reassembly_data_buffer == NULL) {
        printf("!!!memory out of resources!!!\n");
        return;
    }

    size_t fragment_size = buffer_size - starting_offset;
    memcpy(m_reassembly_data_buffer + data_buffer_size, buffer + starting_offset, fragment_size);
    data_buffer_size += fragment_size;

    if (hdr->message_tag & MCTP_HDR_FLAG_EOM) {
        dump_mctp_message((uint8_t *) m_reassembly_data_buffer, data_buffer_size);
        free(m_reassembly_data_buffer);
        m_reassembly_data_buffer = NULL;
        data_buffer_size = 0;
    } else {
        printf("FRAG(");
        if (!m_param_quite_mode) {
            printf("MsgType=%u, Tag=%u, Seq#=%u, ", *(uint8_t *) m_reassembly_data_buffer, hdr->message_tag & 0x7,
                   (hdr->message_tag & 0x30) >> 4);
            dump_entry_flags_all(m_mctp_transport_header_flag_string_table,
                                 LIBSPDM_ARRAY_SIZE(m_mctp_transport_header_flag_string_table),
                                 hdr->message_tag);
        }
        printf(")\n");
    }
}
