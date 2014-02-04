#include "dllstub_def.h"

static const char DLL_NAME[]="wsock32.nt.dll";

DEFINE_FUNC_ORD3(accept,1)
DEFINE_FUNC_ORD3(bind,2)
DEFINE_FUNC_ORD1(closesocket,3)
DEFINE_FUNC_ORD3(connect,4)
DEFINE_FUNC_ORD3(getpeername,5)
DEFINE_FUNC_ORD3(getsockname,6)
DEFINE_FUNC_ORD5(getsockopt,7)
DEFINE_FUNC_ORD1(htonl,8)
DEFINE_FUNC_ORD1(htons,9)
DEFINE_FUNC_ORD1(inet_addr,10)
DEFINE_FUNC_ORD1(inet_ntoa,11)
DEFINE_FUNC_ORD3(ioctlsocket,12)
DEFINE_FUNC_ORD2(listen,13)
DEFINE_FUNC_ORD1(ntohl,14)
DEFINE_FUNC_ORD1(ntohs,15)
DEFINE_FUNC_ORD4(recv,16)
DEFINE_FUNC_ORD6(recvfrom,17)
DEFINE_FUNC_ORD5(select,18)
DEFINE_FUNC_ORD4(send,19)
DEFINE_FUNC_ORD6(sendto,20)
DEFINE_FUNC_ORD5(setsockopt,21)
DEFINE_FUNC_ORD2(shutdown,22)
DEFINE_FUNC_ORD3(socket,23)
DEFINE_FUNC_ORD3(gethostbyaddr,51)
DEFINE_FUNC_ORD1(gethostbyname,52)
DEFINE_FUNC_ORD5(getprotobyname,53)
DEFINE_FUNC_ORD1(getprotobynumber,54)
DEFINE_FUNC_ORD2(getservbyname,55)
DEFINE_FUNC_ORD1(getservbyport,56)
DEFINE_FUNC_ORD2(gethostname,57)
DEFINE_FUNC_ORD4(WSAAsyncSelect,101)
DEFINE_FUNC_ORD6(WSAAsyncGetHostByAddr,102)
DEFINE_FUNC_ORD6(WSAAsyncGetHostByName,103)
DEFINE_FUNC_ORD5(WSAAsyncGetProtoByNumber,104)
DEFINE_FUNC_ORD5(WSAAsyncGetProtoByName,105)
DEFINE_FUNC_ORD6(WSAAsyncGetServByPort,106)
DEFINE_FUNC_ORD5(WSAAsyncGetServByName,107)
DEFINE_FUNC_ORD1(WSACancelAsyncRequest,108)
DEFINE_FUNC_ORD1(WSASetBlockingHook,109)
DEFINE_FUNC_ORD0(WSAUnhookBlockingHook,110)
DEFINE_FUNC_ORD0(WSAGetLastError,111)
DEFINE_FUNC_ORD1(WSASetLastError,112)
DEFINE_FUNC_ORD0(WSACancelBlockingCall,113)
DEFINE_FUNC_ORD0(WSAIsBlocking,114)
DEFINE_FUNC_ORD2(WSAStartup,115)
DEFINE_FUNC_ORD0(WSACleanup,116)
DEFINE_FUNC_ORD2(__WSAFDIsSet,151)
DEFINE_FUNC_ORD0(WEP,500)
DEFINE_FUNC_ORD5(dn_expand,1106)
DEFINE_FUNC_ORD4(WSARecvEx,1107)
DEFINE_FUNC_ORD2(s_perror,1108)
DEFINE_FUNC_ORD10(GetAddressByNameA,1109)
DEFINE_FUNC_ORD10(GetAddressByNameW,1110)
DEFINE_FUNC_ORD3(EnumProtocolsA,1111)
DEFINE_FUNC_ORD3(EnumProtocolsW,1112)
DEFINE_FUNC_ORD2(GetTypeByNameA,1113)
DEFINE_FUNC_ORD2(GetTypeByNameW,1114)
DEFINE_FUNC_ORD3(GetNameByTypeA,1115)
DEFINE_FUNC_ORD3(GetNameByTypeW,1116)
DEFINE_FUNC_ORD6(SetServiceA,1117)
DEFINE_FUNC_ORD6(SetServiceW,1118)
DEFINE_FUNC_ORD7(GetServiceA,1119)
DEFINE_FUNC_ORD7(GetServiceW,1120)
DEFINE_FUNC_ORD3(NPLoadNameSpaces,1130)
DEFINE_FUNC_ORD7(TransmitFile,1140)
DEFINE_FUNC_ORD8(AcceptEx,1141)
DEFINE_FUNC_ORD8(GetAcceptExSockaddrs,1142)
