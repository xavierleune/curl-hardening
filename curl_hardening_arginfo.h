/* This is a generated file, edit curl_hardening.stub.php instead.
 * Stub hash: 3c5d5b100f2f2690f926591a2814619992b483c5 */

#include "zend_constants.h"
#include "zend_enum.h"

ZEND_BEGIN_ARG_INFO_EX(arginfo_class_CurlSocketAddress___construct, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_class_CurlSocket_bind, 0, 1, IS_VOID, 0)
	ZEND_ARG_TYPE_INFO(0, address, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, port, IS_LONG, 0, "0")
ZEND_END_ARG_INFO()

ZEND_METHOD(CurlSocketAddress, __construct);
ZEND_METHOD(CurlSocket, bind);

static const zend_function_entry class_CurlSocketAddress_methods[] = {
	ZEND_ME(CurlSocketAddress, __construct, arginfo_class_CurlSocketAddress___construct, ZEND_ACC_PRIVATE)
	ZEND_FE_END
};

static const zend_function_entry class_CurlSocket_methods[] = {
	ZEND_ME(CurlSocket, bind, arginfo_class_CurlSocket_bind, ZEND_ACC_PUBLIC)
	ZEND_FE_END
};

static void register_curl_hardening_symbols(int module_number)
{
	REGISTER_LONG_CONSTANT("CURLOPT_OPENSOCKETFUNCTION", CURLOPT_OPENSOCKETFUNCTION, CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("CURLSOCKTYPE_IPCXN", CURLSOCKTYPE_IPCXN, CONST_PERSISTENT);
}

static zend_class_entry *register_class_CurlAddressFamily(void)
{
	zend_class_entry *class_entry = zend_register_internal_enum("CurlAddressFamily", IS_UNDEF, NULL);

	zend_enum_add_case_cstr(class_entry, "IpV4", NULL);

	zend_enum_add_case_cstr(class_entry, "IpV6", NULL);

	zend_enum_add_case_cstr(class_entry, "Unix", NULL);

	return class_entry;
}

static zend_class_entry *register_class_CurlSocketAddress(void)
{
	zend_class_entry ce, *class_entry;

	INIT_CLASS_ENTRY(ce, "CurlSocketAddress", class_CurlSocketAddress_methods);
	class_entry = zend_register_internal_class_with_flags(&ce, NULL, ZEND_ACC_FINAL|ZEND_ACC_NO_DYNAMIC_PROPERTIES|ZEND_ACC_NOT_SERIALIZABLE|ZEND_ACC_READONLY_CLASS);

	zval property_family_default_value;
	ZVAL_UNDEF(&property_family_default_value);
	zend_string *property_family_name = zend_string_init("family", sizeof("family") - 1, true);
	zend_string *property_family_class_CurlAddressFamily = zend_string_init("CurlAddressFamily", sizeof("CurlAddressFamily")-1, 1);
	zend_declare_typed_property(class_entry, property_family_name, &property_family_default_value, ZEND_ACC_PUBLIC|ZEND_ACC_READONLY, NULL, (zend_type) ZEND_TYPE_INIT_CLASS(property_family_class_CurlAddressFamily, 0, 0));
	zend_string_release_ex(property_family_name, true);

	zval property_address_default_value;
	ZVAL_UNDEF(&property_address_default_value);
	zend_string *property_address_name = zend_string_init("address", sizeof("address") - 1, true);
	zend_declare_typed_property(class_entry, property_address_name, &property_address_default_value, ZEND_ACC_PUBLIC|ZEND_ACC_READONLY, NULL, (zend_type) ZEND_TYPE_INIT_MASK(MAY_BE_STRING));
	zend_string_release_ex(property_address_name, true);

	zval property_port_default_value;
	ZVAL_UNDEF(&property_port_default_value);
	zend_declare_typed_property(class_entry, ZSTR_KNOWN(ZEND_STR_PORT), &property_port_default_value, ZEND_ACC_PUBLIC|ZEND_ACC_READONLY, NULL, (zend_type) ZEND_TYPE_INIT_MASK(MAY_BE_LONG));

	return class_entry;
}

static zend_class_entry *register_class_CurlSocket(void)
{
	zend_class_entry ce, *class_entry;

	INIT_CLASS_ENTRY(ce, "CurlSocket", class_CurlSocket_methods);
	class_entry = zend_register_internal_class_with_flags(&ce, NULL, ZEND_ACC_FINAL|ZEND_ACC_NO_DYNAMIC_PROPERTIES|ZEND_ACC_NOT_SERIALIZABLE);

	return class_entry;
}
