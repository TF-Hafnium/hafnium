/*
 * Copyright 2024 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/manifest_helpers.h"

#include "hf/check.h"
#include "hf/dlog.h"
#include "hf/fdt.h"
#include "hf/string.h"

enum manifest_return_code read_string(const struct fdt_node *node,
				      const char *property, struct string *out)
{
	struct memiter data;

	if (!fdt_read_property(node, property, &data)) {
		return MANIFEST_ERROR_PROPERTY_NOT_FOUND;
	}

	switch (string_init(out, &data)) {
	case STRING_SUCCESS:
		return MANIFEST_SUCCESS;
	case STRING_ERROR_INVALID_INPUT:
		return MANIFEST_ERROR_MALFORMED_STRING;
	case STRING_ERROR_TOO_LONG:
		return MANIFEST_ERROR_STRING_TOO_LONG;
	}
}

enum manifest_return_code read_optional_string(const struct fdt_node *node,
					       const char *property,
					       struct string *out)
{
	enum manifest_return_code ret;

	ret = read_string(node, property, out);
	if (ret == MANIFEST_ERROR_PROPERTY_NOT_FOUND) {
		string_init_empty(out);
		ret = MANIFEST_SUCCESS;
	}
	return ret;
}

enum manifest_return_code read_uint32list(const struct fdt_node *node,
					  const char *property,
					  struct uint32list_iter *out)
{
	struct memiter data;

	if (!fdt_read_property(node, property, &data)) {
		memiter_init(&out->mem_it, NULL, 0);
		return MANIFEST_ERROR_PROPERTY_NOT_FOUND;
	}

	if ((memiter_size(&data) % sizeof(uint32_t)) != 0) {
		return MANIFEST_ERROR_MALFORMED_INTEGER_LIST;
	}

	out->mem_it = data;
	return MANIFEST_SUCCESS;
}

enum manifest_return_code read_optional_uint32list(const struct fdt_node *node,
						   const char *property,
						   struct uint32list_iter *out)
{
	enum manifest_return_code ret = read_uint32list(node, property, out);

	if (ret == MANIFEST_ERROR_PROPERTY_NOT_FOUND) {
		return MANIFEST_SUCCESS;
	}
	return ret;
}

bool uint32list_has_next(const struct uint32list_iter *list)
{
	return memiter_size(&list->mem_it) > 0;
}

enum manifest_return_code uint32list_get_next(struct uint32list_iter *list,
					      uint32_t *out)
{
	uint64_t num;

	CHECK(uint32list_has_next(list));
	if (!fdt_parse_number(&list->mem_it, sizeof(uint32_t), &num)) {
		return MANIFEST_ERROR_MALFORMED_INTEGER;
	}

	*out = (uint32_t)num;
	return MANIFEST_SUCCESS;
}

static int hex_val(char c)
{
	if ('0' <= c && c <= '9') {
		return c - '0';
	}
	if ('a' <= c && c <= 'f') {
		return c - 'a' + 10;
	}
	if ('A' <= c && c <= 'F') {
		return c - 'A' + 10;
	}
	return -1;  // invalid
}

static enum manifest_return_code parse_hexOctet(const char hi_char,
						const char lo_char,
						uint8_t *out)
{
	int high_nibble = hex_val(hi_char);
	int low_nibble = hex_val(lo_char);

	if (high_nibble == -1 || low_nibble == -1) {
		return MANIFEST_ERROR_MALFORMED_UUID;
	}

	*out = (uint8_t)((high_nibble << 4) | low_nibble);
	return MANIFEST_SUCCESS;
}

#define UUID_STRING_LENGTH 36
#define UUID_STRING_FIRST_HYPHEN_INDEX 8
#define UUID_STRING_SECOND_HYPHEN_INDEX 13
#define UUID_STRING_THIRD_HYPHEN_INDEX 18
#define UUID_STRING_FOURTH_HYPHEN_INDEX 23

/**
 * Parse a UUID string in canonical form
 * "00112233-4455-6677-8899-aabbccddeeff"
 * into the ffa_uuid layout of four uint32_t words:
 * {0x00112233, 0x44556677, 0x8899aabb, 0xccddeeff}
 */
static enum manifest_return_code str_uuid_to_ffa_uuid(const char *str_uuid,
						      struct ffa_uuid *ffa_uuid)
{
	uint8_t bytes[16];
	uint8_t *cur_byte = bytes;
	char hi;
	char lo;
	int i = 0;

	while (i < UUID_STRING_LENGTH) {
		/* Check dashes are in the correct place and skip over them. */
		if (i == UUID_STRING_FIRST_HYPHEN_INDEX ||
		    i == UUID_STRING_SECOND_HYPHEN_INDEX ||
		    i == UUID_STRING_THIRD_HYPHEN_INDEX ||
		    i == UUID_STRING_FOURTH_HYPHEN_INDEX) {
			if (str_uuid[i] != '-') {
				return MANIFEST_ERROR_MALFORMED_UUID;
			}
			i++;
		}
		/*
		 * For a canonical UUID like
		 * "00112233-4455-6677-8899-aabbccddeeff" take each hex pair
		 * (e.g. '00', then '11', ...) and turn it into the
		 * corresponding byte.
		 */
		hi = str_uuid[i++];
		lo = str_uuid[i++];

		TRY(parse_hexOctet(hi, lo, cur_byte++));
	}

	if (str_uuid[i] != 0) {
		return MANIFEST_ERROR_MALFORMED_UUID;
	}

	ffa_uuid->uuid[0] =
		(bytes[0] << 24 | bytes[1] << 16 | bytes[2] << 8 | bytes[3]);
	ffa_uuid->uuid[1] =
		(bytes[4] << 24 | bytes[5] << 16 | bytes[6] << 8 | bytes[7]);
	ffa_uuid->uuid[2] =
		(bytes[8] << 24 | bytes[9] << 16 | bytes[10] << 8 | bytes[11]);
	ffa_uuid->uuid[3] = (bytes[12] << 24 | bytes[13] << 16 |
			     bytes[14] << 8 | bytes[15]);

	return MANIFEST_SUCCESS;
}

/**
 * Parse a UUID in the uint32 list format from `uuid` into `out`.
 * Returns `MANIFEST_SUCCESS` if parsing succeeded.
 */
static enum manifest_return_code parse_flattened_uuid(
	struct uint32list_iter *uuid, struct ffa_uuid *out)
{
	for (size_t i = 0; i < 4 && uint32list_has_next(uuid); i++) {
		TRY(uint32list_get_next(uuid, &out->uuid[i]));
	}

	dlog_verbose("  UUID %#x-%x-%x-%x\n", out->uuid[0], out->uuid[1],
		     out->uuid[2], out->uuid[3]);

	if (ffa_uuid_is_null(out)) {
		return MANIFEST_ERROR_UUID_ALL_ZEROS;
	}

	return MANIFEST_SUCCESS;
}

/**
 * Parse a UUID in the canonical string format from `uuid` into `out`
 * Returns `MANIFEST_SUCCESS` if parsing succeeded.
 */
static enum manifest_return_code parse_canonical_uuid(struct string *uuid,
						      struct ffa_uuid *out)
{
	/*
	 * Cannonical UUID format is hexOctets of length 4,2,2,2,6
	 * separated by a -.
	 * This needs converting to 4 uint32_t values for storing.
	 */
	TRY(str_uuid_to_ffa_uuid(&uuid->data[0], out));

	dlog_verbose("  UUID %#x-%x-%x-%x\n", out->uuid[0], out->uuid[1],
		     out->uuid[2], out->uuid[3]);

	if (ffa_uuid_is_null(out)) {
		return MANIFEST_ERROR_UUID_ALL_ZEROS;
	}

	return MANIFEST_SUCCESS;
}

static enum manifest_return_code parse_messaging_method(
	struct uint32list_iter *messaging_method, uint16_t *out)
{
	uint32_t value;

	TRY(uint32list_get_next(messaging_method, &value));
	if (value > UINT16_MAX) {
		return MANIFEST_ERROR_INTEGER_OVERFLOW;
	}
	if (value == 0 ||
	    (value &
	     ~(FFA_PARTITION_DIRECT_REQ_RECV | FFA_PARTITION_DIRECT_REQ_SEND |
	       FFA_PARTITION_INDIRECT_MSG | FFA_PARTITION_DIRECT_REQ2_RECV |
	       FFA_PARTITION_DIRECT_REQ2_SEND)) != 0U) {
		dlog_error(
			"Messaging method specified in the manifest is not "
			"supported: %x\n",
			value);
		return MANIFEST_ERROR_INVALID_MESSAGING_METHOD;
	}

	*out = (uint16_t)value;

	return MANIFEST_SUCCESS;
}

/**
 * Populate the services structs from the uuid list and messaging method list
 * provided in v1.0 manifest. If only one messaging method is provided it
 * applies to all UUIDs.
 */
static enum manifest_return_code parse_services_v1_0(
	const struct fdt_node *node, struct service *services,
	uint16_t *service_count)
{
	struct uint32list_iter uuid;
	struct uint32list_iter messaging_method;
	uint16_t shared_messaging_method_value = 0;

	*service_count = 0;

	TRY(read_uint32list(node, "uuid", &uuid));
	TRY(read_uint32list(node, "messaging-method", &messaging_method));

	while (uint32list_has_next(&uuid)) {
		if (*service_count == PARTITION_MAX_UUIDS) {
			return MANIFEST_ERROR_TOO_MANY_UUIDS;
		}
		TRY(parse_flattened_uuid(&uuid,
					 &services[*service_count].uuid));
		/*
		 * If only one messaging method is provided, record it
		 * and apply it to all services. By definition the value
		 * must be non-zero so this can be used to see if a
		 * value has been recorded to use.
		 */
		if (shared_messaging_method_value != 0) {
			services[*service_count].messaging_method =
				shared_messaging_method_value;
		} else {
			if (!uint32list_has_next(&messaging_method)) {
				return MANIFEST_ERROR_UNMATCHED_MESSAGING_METHODS;
			}
			TRY(parse_messaging_method(
				&messaging_method,
				&services[*service_count].messaging_method));

			/*
			 * Check if there is a second messaging method present.
			 * If not use the first messaging method for all
			 * services.
			 */
			if (*service_count == 0 &&
			    !uint32list_has_next(&messaging_method)) {
				shared_messaging_method_value =
					services[*service_count]
						.messaging_method;
			}
		}

		(*service_count)++;
	}

	/*
	 * Check there are no more messaging methods defined that don't
	 * match with a UUID.
	 */
	if (uint32list_has_next(&messaging_method)) {
		return MANIFEST_ERROR_UNMATCHED_MESSAGING_METHODS;
	}

	return MANIFEST_SUCCESS;
}

/**
 * Populate the services array from the service structs.
 */
static enum manifest_return_code parse_services_v1_1(
	const struct fdt_node *node, struct service *services,
	uint16_t *service_count)
{
	struct fdt_node services_node = *node;
	struct string services_node_name = STRING_INIT("services");
	struct string uuid;
	struct uint32list_iter messaging_method;

	*service_count = 0;

	if (!fdt_find_child(&services_node, &services_node_name)) {
		return MANIFEST_ERROR_NO_SERVICES;
	}
	if (!fdt_is_compatible(&services_node, "arm,ffa-manifest-services")) {
		return MANIFEST_ERROR_NOT_COMPATIBLE;
	}
	if (!fdt_first_child(&services_node)) {
		return MANIFEST_ERROR_NO_SERVICES;
	}

	do {
		if (*service_count == PARTITION_MAX_UUIDS) {
			return MANIFEST_ERROR_TOO_MANY_UUIDS;
		}

		TRY(read_string(&services_node, "uuid", &uuid));
		TRY(read_uint32list(&services_node, "messaging-method",
				    &messaging_method));

		TRY(parse_canonical_uuid(&uuid,
					 &services[*service_count].uuid));

		TRY(parse_messaging_method(
			&messaging_method,
			&services[*service_count].messaging_method));
		(*service_count)++;
	} while (fdt_next_sibling(&services_node));

	return MANIFEST_SUCCESS;
}

enum manifest_return_code parse_services(const struct fdt_node *node,
					 struct service *services,
					 uint16_t *service_count,
					 uint16_t manifest_version_minor)
{
	if (manifest_version_minor == 0) {
		TRY(parse_services_v1_0(node, services, service_count));
	} else {
		TRY(parse_services_v1_1(node, services, service_count));
	}

	dlog_verbose("  Service Count %u\n", *service_count);
	for (int i = 0; i < *service_count; i++) {
		dlog_verbose("  UUID %#x-%x-%x-%x\n", services[i].uuid.uuid[0],
			     services[i].uuid.uuid[1], services[i].uuid.uuid[2],
			     services[i].uuid.uuid[3]);
		dlog_verbose("  Messaging Methods %#x\n",
			     services[i].messaging_method);
	}

	return MANIFEST_SUCCESS;
}
