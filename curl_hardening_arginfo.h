/* This is a generated file, edit curl_hardening.stub.php instead.
 * Stub hash: aa9850fca4d4bfd7e47b4465b260ca8d7aafc3e5 */

#include "zend_constants.h"
#include "zend_enum.h"

static void register_curl_hardening_symbols(int module_number)
{
	REGISTER_LONG_CONSTANT("CURLOPT_OPENSOCKETFUNCTION", CURLOPT_OPENSOCKETFUNCTION, CONST_PERSISTENT);
}

static zend_class_entry *register_class_CurlAddressFamily(void)
{
	zend_class_entry *class_entry = zend_register_internal_enum("CurlAddressFamily", IS_UNDEF, NULL);

	zend_enum_add_case_cstr(class_entry, "IpV4", NULL);

	zend_enum_add_case_cstr(class_entry, "IpV6", NULL);

	zend_enum_add_case_cstr(class_entry, "Unix", NULL);

	return class_entry;
}
