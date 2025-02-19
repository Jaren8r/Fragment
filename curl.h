#pragma once

typedef long CURLcode;
typedef int CURLoption;
const CURLoption CURLOPT_URL = 10002;

typedef CURLcode(*CurlSetoptFn)(void*, CURLoption, va_list);