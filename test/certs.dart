// Copyright (c) 2024 Jan Romann
// SPDX-License-Identifier: MIT

const rawPemCertificate = """
-----BEGIN CERTIFICATE-----
MIIFYDCCBEigAwIBAgIQQAF3ITfU6UK47naqPGQKtzANBgkqhkiG9w0BAQsFADA/
MSQwIgYDVQQKExtEaWdpdGFsIFNpZ25hdHVyZSBUcnVzdCBDby4xFzAVBgNVBAMT
DkRTVCBSb290IENBIFgzMB4XDTIxMDEyMDE5MTQwM1oXDTI0MDkzMDE4MTQwM1ow
TzELMAkGA1UEBhMCVVMxKTAnBgNVBAoTIEludGVybmV0IFNlY3VyaXR5IFJlc2Vh
cmNoIEdyb3VwMRUwEwYDVQQDEwxJU1JHIFJvb3QgWDEwggIiMA0GCSqGSIb3DQEB
AQUAA4ICDwAwggIKAoICAQCt6CRz9BQ385ueK1coHIe+3LffOJCMbjzmV6B493XC
ov71am72AE8o295ohmxEk7axY/0UEmu/H9LqMZshftEzPLpI9d1537O4/xLxIZpL
wYqGcWlKZmZsj348cL+tKSIG8+TA5oCu4kuPt5l+lAOf00eXfJlII1PoOK5PCm+D
LtFJV4yAdLbaL9A4jXsDcCEbdfIwPPqPrt3aY6vrFk/CjhFLfs8L6P+1dy70sntK
4EwSJQxwjQMpoOFTJOwT2e4ZvxCzSow/iaNhUd6shweU9GNx7C7ib1uYgeGJXDR5
bHbvO5BieebbpJovJsXQEOEO3tkQjhb7t/eo98flAgeYjzYIlefiN5YNNnWe+w5y
sR2bvAP5SQXYgd0FtCrWQemsAXaVCg/Y39W9Eh81LygXbNKYwagJZHduRze6zqxZ
Xmidf3LWicUGQSk+WT7dJvUkyRGnWqNMQB9GoZm1pzpRboY7nn1ypxIFeFntPlF4
FQsDj43QLwWyPntKHEtzBRL8xurgUBN8Q5N0s8p0544fAQjQMNRbcTa0B7rBMDBc
SLeCO5imfWCKoqMpgsy6vYMEG6KDA0Gh1gXxG8K28Kh8hjtGqEgqiNx2mna/H2ql
PRmP6zjzZN7IKw0KKP/32+IVQtQi0Cdd4Xn+GOdwiK1O5tmLOsbdJ1Fu/7xk9TND
TwIDAQABo4IBRjCCAUIwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYw
SwYIKwYBBQUHAQEEPzA9MDsGCCsGAQUFBzAChi9odHRwOi8vYXBwcy5pZGVudHJ1
c3QuY29tL3Jvb3RzL2RzdHJvb3RjYXgzLnA3YzAfBgNVHSMEGDAWgBTEp7Gkeyxx
+tvhS5B1/8QVYIWJEDBUBgNVHSAETTBLMAgGBmeBDAECATA/BgsrBgEEAYLfEwEB
ATAwMC4GCCsGAQUFBwIBFiJodHRwOi8vY3BzLnJvb3QteDEubGV0c2VuY3J5cHQu
b3JnMDwGA1UdHwQ1MDMwMaAvoC2GK2h0dHA6Ly9jcmwuaWRlbnRydXN0LmNvbS9E
U1RST09UQ0FYM0NSTC5jcmwwHQYDVR0OBBYEFHm0WeZ7tuXkAXOACIjIGlj26Ztu
MA0GCSqGSIb3DQEBCwUAA4IBAQAKcwBslm7/DlLQrt2M51oGrS+o44+/yQoDFVDC
5WxCu2+b9LRPwkSICHXM6webFGJueN7sJ7o5XPWioW5WlHAQU7G75K/QosMrAdSW
9MUgNTP52GE24HGNtLi1qoJFlcDyqSMo59ahy2cI2qBDLKobkx/J3vWraV0T9VuG
WCLKTVXkcGdtwlfFRjlBz4pYg1htmf5X6DYO8A4jqv2Il9DjXA6USbW1FzXSLr9O
he8Y4IWS6wY7bCkjCWDcRQJMEhg76fsO3txE+FiYruq9RUWhiF1myv4Q6W+CyBFC
Dfvp7OOGAN6dEOM4+qR9sdjoSYKEBpsr6GtPAQw4dy753ec5
-----END CERTIFICATE-----
""";

const rawDerCertificate = [
  48,
  130,
  5,
  107,
  48,
  130,
  3,
  83,
  160,
  3,
  2,
  1,
  2,
  2,
  17,
  0,
  130,
  16,
  207,
  176,
  210,
  64,
  227,
  89,
  68,
  99,
  224,
  187,
  99,
  130,
  139,
  0,
  48,
  13,
  6,
  9,
  42,
  134,
  72,
  134,
  247,
  13,
  1,
  1,
  11,
  5,
  0,
  48,
  79,
  49,
  11,
  48,
  9,
  6,
  3,
  85,
  4,
  6,
  19,
  2,
  85,
  83,
  49,
  41,
  48,
  39,
  6,
  3,
  85,
  4,
  10,
  19,
  32,
  73,
  110,
  116,
  101,
  114,
  110,
  101,
  116,
  32,
  83,
  101,
  99,
  117,
  114,
  105,
  116,
  121,
  32,
  82,
  101,
  115,
  101,
  97,
  114,
  99,
  104,
  32,
  71,
  114,
  111,
  117,
  112,
  49,
  21,
  48,
  19,
  6,
  3,
  85,
  4,
  3,
  19,
  12,
  73,
  83,
  82,
  71,
  32,
  82,
  111,
  111,
  116,
  32,
  88,
  49,
  48,
  30,
  23,
  13,
  49,
  53,
  48,
  54,
  48,
  52,
  49,
  49,
  48,
  52,
  51,
  56,
  90,
  23,
  13,
  51,
  53,
  48,
  54,
  48,
  52,
  49,
  49,
  48,
  52,
  51,
  56,
  90,
  48,
  79,
  49,
  11,
  48,
  9,
  6,
  3,
  85,
  4,
  6,
  19,
  2,
  85,
  83,
  49,
  41,
  48,
  39,
  6,
  3,
  85,
  4,
  10,
  19,
  32,
  73,
  110,
  116,
  101,
  114,
  110,
  101,
  116,
  32,
  83,
  101,
  99,
  117,
  114,
  105,
  116,
  121,
  32,
  82,
  101,
  115,
  101,
  97,
  114,
  99,
  104,
  32,
  71,
  114,
  111,
  117,
  112,
  49,
  21,
  48,
  19,
  6,
  3,
  85,
  4,
  3,
  19,
  12,
  73,
  83,
  82,
  71,
  32,
  82,
  111,
  111,
  116,
  32,
  88,
  49,
  48,
  130,
  2,
  34,
  48,
  13,
  6,
  9,
  42,
  134,
  72,
  134,
  247,
  13,
  1,
  1,
  1,
  5,
  0,
  3,
  130,
  2,
  15,
  0,
  48,
  130,
  2,
  10,
  2,
  130,
  2,
  1,
  0,
  173,
  232,
  36,
  115,
  244,
  20,
  55,
  243,
  155,
  158,
  43,
  87,
  40,
  28,
  135,
  190,
  220,
  183,
  223,
  56,
  144,
  140,
  110,
  60,
  230,
  87,
  160,
  120,
  247,
  117,
  194,
  162,
  254,
  245,
  106,
  110,
  246,
  0,
  79,
  40,
  219,
  222,
  104,
  134,
  108,
  68,
  147,
  182,
  177,
  99,
  253,
  20,
  18,
  107,
  191,
  31,
  210,
  234,
  49,
  155,
  33,
  126,
  209,
  51,
  60,
  186,
  72,
  245,
  221,
  121,
  223,
  179,
  184,
  255,
  18,
  241,
  33,
  154,
  75,
  193,
  138,
  134,
  113,
  105,
  74,
  102,
  102,
  108,
  143,
  126,
  60,
  112,
  191,
  173,
  41,
  34,
  6,
  243,
  228,
  192,
  230,
  128,
  174,
  226,
  75,
  143,
  183,
  153,
  126,
  148,
  3,
  159,
  211,
  71,
  151,
  124,
  153,
  72,
  35,
  83,
  232,
  56,
  174,
  79,
  10,
  111,
  131,
  46,
  209,
  73,
  87,
  140,
  128,
  116,
  182,
  218,
  47,
  208,
  56,
  141,
  123,
  3,
  112,
  33,
  27,
  117,
  242,
  48,
  60,
  250,
  143,
  174,
  221,
  218,
  99,
  171,
  235,
  22,
  79,
  194,
  142,
  17,
  75,
  126,
  207,
  11,
  232,
  255,
  181,
  119,
  46,
  244,
  178,
  123,
  74,
  224,
  76,
  18,
  37,
  12,
  112,
  141,
  3,
  41,
  160,
  225,
  83,
  36,
  236,
  19,
  217,
  238,
  25,
  191,
  16,
  179,
  74,
  140,
  63,
  137,
  163,
  97,
  81,
  222,
  172,
  135,
  7,
  148,
  244,
  99,
  113,
  236,
  46,
  226,
  111,
  91,
  152,
  129,
  225,
  137,
  92,
  52,
  121,
  108,
  118,
  239,
  59,
  144,
  98,
  121,
  230,
  219,
  164,
  154,
  47,
  38,
  197,
  208,
  16,
  225,
  14,
  222,
  217,
  16,
  142,
  22,
  251,
  183,
  247,
  168,
  247,
  199,
  229,
  2,
  7,
  152,
  143,
  54,
  8,
  149,
  231,
  226,
  55,
  150,
  13,
  54,
  117,
  158,
  251,
  14,
  114,
  177,
  29,
  155,
  188,
  3,
  249,
  73,
  5,
  216,
  129,
  221,
  5,
  180,
  42,
  214,
  65,
  233,
  172,
  1,
  118,
  149,
  10,
  15,
  216,
  223,
  213,
  189,
  18,
  31,
  53,
  47,
  40,
  23,
  108,
  210,
  152,
  193,
  168,
  9,
  100,
  119,
  110,
  71,
  55,
  186,
  206,
  172,
  89,
  94,
  104,
  157,
  127,
  114,
  214,
  137,
  197,
  6,
  65,
  41,
  62,
  89,
  62,
  221,
  38,
  245,
  36,
  201,
  17,
  167,
  90,
  163,
  76,
  64,
  31,
  70,
  161,
  153,
  181,
  167,
  58,
  81,
  110,
  134,
  59,
  158,
  125,
  114,
  167,
  18,
  5,
  120,
  89,
  237,
  62,
  81,
  120,
  21,
  11,
  3,
  143,
  141,
  208,
  47,
  5,
  178,
  62,
  123,
  74,
  28,
  75,
  115,
  5,
  18,
  252,
  198,
  234,
  224,
  80,
  19,
  124,
  67,
  147,
  116,
  179,
  202,
  116,
  231,
  142,
  31,
  1,
  8,
  208,
  48,
  212,
  91,
  113,
  54,
  180,
  7,
  186,
  193,
  48,
  48,
  92,
  72,
  183,
  130,
  59,
  152,
  166,
  125,
  96,
  138,
  162,
  163,
  41,
  130,
  204,
  186,
  189,
  131,
  4,
  27,
  162,
  131,
  3,
  65,
  161,
  214,
  5,
  241,
  27,
  194,
  182,
  240,
  168,
  124,
  134,
  59,
  70,
  168,
  72,
  42,
  136,
  220,
  118,
  154,
  118,
  191,
  31,
  106,
  165,
  61,
  25,
  143,
  235,
  56,
  243,
  100,
  222,
  200,
  43,
  13,
  10,
  40,
  255,
  247,
  219,
  226,
  21,
  66,
  212,
  34,
  208,
  39,
  93,
  225,
  121,
  254,
  24,
  231,
  112,
  136,
  173,
  78,
  230,
  217,
  139,
  58,
  198,
  221,
  39,
  81,
  110,
  255,
  188,
  100,
  245,
  51,
  67,
  79,
  2,
  3,
  1,
  0,
  1,
  163,
  66,
  48,
  64,
  48,
  14,
  6,
  3,
  85,
  29,
  15,
  1,
  1,
  255,
  4,
  4,
  3,
  2,
  1,
  6,
  48,
  15,
  6,
  3,
  85,
  29,
  19,
  1,
  1,
  255,
  4,
  5,
  48,
  3,
  1,
  1,
  255,
  48,
  29,
  6,
  3,
  85,
  29,
  14,
  4,
  22,
  4,
  20,
  121,
  180,
  89,
  230,
  123,
  182,
  229,
  228,
  1,
  115,
  128,
  8,
  136,
  200,
  26,
  88,
  246,
  233,
  155,
  110,
  48,
  13,
  6,
  9,
  42,
  134,
  72,
  134,
  247,
  13,
  1,
  1,
  11,
  5,
  0,
  3,
  130,
  2,
  1,
  0,
  85,
  31,
  88,
  169,
  188,
  178,
  168,
  80,
  208,
  12,
  177,
  216,
  26,
  105,
  32,
  39,
  41,
  8,
  172,
  97,
  117,
  92,
  138,
  110,
  248,
  130,
  229,
  105,
  47,
  213,
  246,
  86,
  75,
  185,
  184,
  115,
  16,
  89,
  211,
  33,
  151,
  126,
  231,
  76,
  113,
  251,
  178,
  210,
  96,
  173,
  57,
  168,
  11,
  234,
  23,
  33,
  86,
  133,
  241,
  80,
  14,
  89,
  235,
  206,
  224,
  89,
  233,
  186,
  201,
  21,
  239,
  134,
  157,
  143,
  132,
  128,
  246,
  228,
  233,
  145,
  144,
  220,
  23,
  155,
  98,
  27,
  69,
  240,
  102,
  149,
  210,
  124,
  111,
  194,
  234,
  59,
  239,
  31,
  207,
  203,
  214,
  174,
  39,
  241,
  169,
  176,
  200,
  174,
  253,
  125,
  126,
  154,
  250,
  34,
  4,
  235,
  255,
  217,
  127,
  234,
  145,
  43,
  34,
  177,
  23,
  14,
  143,
  242,
  138,
  52,
  91,
  88,
  216,
  252,
  1,
  201,
  84,
  185,
  184,
  38,
  204,
  138,
  136,
  51,
  137,
  76,
  45,
  132,
  60,
  130,
  223,
  238,
  150,
  87,
  5,
  186,
  44,
  187,
  247,
  196,
  183,
  199,
  78,
  59,
  130,
  190,
  49,
  200,
  34,
  115,
  115,
  146,
  209,
  194,
  128,
  164,
  57,
  57,
  16,
  51,
  35,
  130,
  76,
  60,
  159,
  134,
  178,
  85,
  152,
  29,
  190,
  41,
  134,
  140,
  34,
  155,
  158,
  226,
  107,
  59,
  87,
  58,
  130,
  112,
  77,
  220,
  9,
  199,
  137,
  203,
  10,
  7,
  77,
  108,
  232,
  93,
  142,
  201,
  239,
  206,
  171,
  199,
  187,
  181,
  43,
  78,
  69,
  214,
  74,
  208,
  38,
  204,
  229,
  114,
  202,
  8,
  106,
  165,
  149,
  227,
  21,
  161,
  247,
  164,
  237,
  201,
  44,
  95,
  165,
  251,
  255,
  172,
  40,
  2,
  46,
  190,
  215,
  123,
  187,
  227,
  113,
  123,
  144,
  22,
  211,
  7,
  94,
  70,
  83,
  124,
  55,
  7,
  66,
  140,
  211,
  196,
  150,
  156,
  213,
  153,
  181,
  42,
  224,
  149,
  26,
  128,
  72,
  174,
  76,
  57,
  7,
  206,
  204,
  71,
  164,
  82,
  149,
  43,
  186,
  184,
  251,
  173,
  210,
  51,
  83,
  125,
  229,
  29,
  77,
  109,
  213,
  161,
  177,
  199,
  66,
  111,
  230,
  64,
  39,
  53,
  92,
  163,
  40,
  183,
  7,
  141,
  231,
  141,
  51,
  144,
  231,
  35,
  159,
  251,
  80,
  156,
  121,
  108,
  70,
  213,
  180,
  21,
  179,
  150,
  110,
  126,
  155,
  12,
  150,
  58,
  184,
  82,
  45,
  63,
  214,
  91,
  225,
  251,
  8,
  194,
  132,
  254,
  36,
  168,
  163,
  137,
  218,
  172,
  106,
  225,
  24,
  42,
  177,
  168,
  67,
  97,
  91,
  211,
  31,
  220,
  59,
  141,
  118,
  242,
  45,
  232,
  141,
  117,
  223,
  23,
  51,
  108,
  61,
  83,
  251,
  123,
  203,
  65,
  95,
  255,
  220,
  162,
  208,
  97,
  56,
  225,
  150,
  184,
  172,
  93,
  139,
  55,
  215,
  117,
  213,
  51,
  192,
  153,
  17,
  174,
  157,
  65,
  193,
  114,
  117,
  132,
  190,
  2,
  65,
  66,
  95,
  103,
  36,
  72,
  148,
  209,
  155,
  39,
  190,
  7,
  63,
  185,
  184,
  79,
  129,
  116,
  81,
  225,
  122,
  183,
  237,
  157,
  35,
  226,
  190,
  224,
  213,
  40,
  4,
  19,
  60,
  49,
  3,
  158,
  221,
  122,
  108,
  143,
  198,
  7,
  24,
  198,
  127,
  222,
  71,
  142,
  63,
  40,
  158,
  4,
  6,
  207,
  165,
  84,
  52,
  119,
  189,
  236,
  137,
  155,
  233,
  23,
  67,
  223,
  91,
  219,
  95,
  254,
  142,
  30,
  87,
  162,
  205,
  64,
  157,
  126,
  98,
  34,
  218,
  222,
  24,
  39,
];
