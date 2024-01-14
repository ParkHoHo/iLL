> 코드의 진위, 코드의 출처를 나타내는 기법으로 Code Sign을 진행.

# 👉🏻 코드서명 포맷

## ☝🏻 LC_CODE_SIGNATURE && SuperBlob

> `LC_CODE_SIGNATURE` 는 macOS의 바이너리 파일에 대한 코드서명을 포함하는데 사용하는 로드 명령을 의미한다.
> 그렇기에 사이닝이 끝난 후에 `LC_CODE_SIGNATURE` 로드 명령어가 실행된다.

`LC_CODE_SIGNATURE`은 `__LINKEDIT` 이라는 로드명령 구조를 따른다. 이는 /kern/cs_blob.h에서 확인할 수 있었다.

```header
typedef struct __BlobIndex {
	uint32_t type;                                  /* type of entry */
	uint32_t offset;                                /* offset of entry */
} CS_BlobIndex
__attribute__ ((aligned(1)));

typedef struct __SC_SuperBlob {
	uint32_t magic;                                 /* magic number */
	uint32_t length;                                /* total length of SuperBlob */
	uint32_t count;                                 /* number of index entries following */
	CS_BlobIndex index[];                   /* (count) entries */
	/* followed by Blobs in no particular order as indicated by offsets in index */
} CS_SuperBlob
__attribute__ ((aligned(1)));

```

> 위의 코드에서는 SuperBlob이라는 용어가 나오는데 이는 블롭의 블롭, 즉, 서브 블롭을 의미한다.

[참고](https://github.com/qyang-nj/llios/blob/main/macho_parser/docs/LC_CODE_SIGNATURE.md)

앞서 말했듯이 서명 블롭은 파일의 끝에 존재한다. 그렇기에 서명 블롭만을 따로 떼어낼 수 있는데, 방식은 다음과 같다.

```bash
> ARCH=arm64e jtool2 -l /bin/ls | grep SIG                                                                                                              ─╯
LC 18: LC_CODE_SIGNATURE     	Offset:     , Size:  18848
```

위의 커맨드를 통해 signature의 offset을 알아내었다.

```bash
> dd if=/bin/ls of=ls.sig bs=$(offset) skip=1                                                                                                               ─╯
1+1 records in
1+1 records out
```

그 후에 dd 명령어를 이용해서 추출을 하였다.

> [!info] > `dd 명령어`는 파일이나 데이터 스트림을 변환하고 복사하는데 사용된다.
> 사용 방법은 `dd if=입력파일 of=출력파일 bs=blocksize` 다.

```bash
file ls.sig                                                                                                                                           ─╯
ls.sig: data
```

마지막으로 file을 통해 data blob을 확인하였다.

이외에도 jtool2를 이용하여 블롭을 추출할 수 있다.
하지만 최신 MACOS에서 시스템 바이너리와 같은 파일들은 코드 서명이 따로 없다.
그렇기에 따로 추출할 수 있는 방식으로는 appstore에서 설치한 앱의 바이너리 파일을 가져와서 분석을 진행해보면 어떨까? 라는 생각이 들었고, 이를 실행하였다.

> [!error] > </br>
> 확인 결과 일반 앱을 대상으로도 코드 사인 추출이 불가능하였음. 특히 jtool2를 통한 추출이 불가능하였음.

```bash
jtool2 -e signature ./DVIA-v2                                                                                                                         ─╯
Note: 70910 symbols detected in this file! This will take a little while - generate a companion file or use '-q' for quick mode..
signature not found in file
```

따라서 od를 통한 code-sign 추출을 진행하고, 이를 읽어오는 커맨드를 실행해보았음.

```bash
❯ file DVIA.sig                                                                                                                                         ─╯
DVIA.sig: Mac OS X Detached Code Signature (non-executable) - 100209 bytes
```

확인 결과 macosX에서의 Code sign임을 확인하였고,
od 명령어를 통한 결과를 확인해봤을 때 magic number가 다음과 같았음.

```bash
❯ od -N 512 -t x1 -A x DVIA.sig                                                                                                                         ─╯
0000000    fa  de  0c  c0  00  01  87  71  00  00  00  05  00  00  00  00
0000010
0000020
0000030
0000040
0000050
0000060
0000070
0000080
0000090
00000a0
00000b0
00000c0
00000d0
00000e0
00000f0
0000100
0000110
0000120
0000130
0000140
0000150
0000160
0000170
0000180
0000190
00001a0
00001b0
00001c0
00001d0
00001e0
00001f0
0000200
```

## ✌🏻 Code Directory Blob

> 서명되는 자원과 관련된 필수적인 메타 데이터와 이러한 자원, 바이너리 내의 코드 페이지

`Code Directory Blob`은 다음과 같이 정의되어 있다.

```cs_blob.h
/*
 * C form of a CodeDirectory.
 */
typedef struct __CodeDirectory {
	uint32_t magic;                                 /* magic number (CSMAGIC_CODEDIRECTORY) */
	uint32_t length;                                /* total length of CodeDirectory blob */
	uint32_t version;                               /* compatibility version */
	uint32_t flags;                                 /* setup and mode flags */
	uint32_t hashOffset;                    /* offset of hash slot element at index zero */
	uint32_t identOffset;                   /* offset of identifier string */
	uint32_t nSpecialSlots;                 /* number of special hash slots */
	uint32_t nCodeSlots;                    /* number of ordinary (code) hash slots */
	uint32_t codeLimit;                             /* limit to main image signature range */
	uint8_t hashSize;                               /* size of each hash in bytes */
	uint8_t hashType;                               /* type of hash (cdHashType* constants) */
	uint8_t platform;                               /* platform identifier; zero if not platform binary */
	uint8_t pageSize;                               /* log2(page size in bytes); 0 => infinite */
	uint32_t spare2;                                /* unused (must be zero) */

	char end_earliest[0];

	/* Version 0x20100 */
	uint32_t scatterOffset;                 /* offset of optional scatter vector */
	char end_withScatter[0];

	/* Version 0x20200 */
	uint32_t teamOffset;                    /* offset of optional team identifier */
	char end_withTeam[0];

	/* Version 0x20300 */
	uint32_t spare3;                                /* unused (must be zero) */
	uint64_t codeLimit64;                   /* limit to main image signature range, 64 bits */
	char end_withCodeLimit64[0];

	/* Version 0x20400 */
	uint64_t execSegBase;                   /* offset of executable segment */
	uint64_t execSegLimit;                  /* limit of executable segment */
	uint64_t execSegFlags;                  /* executable segment flags */
	char end_withExecSeg[0];
	/* Version 0x20500 */
	uint32_t runtime;
	uint32_t preEncryptOffset;
	char end_withPreEncryptOffset[0];

	/* Version 0x20600 */
	uint8_t linkageHashType;
	uint8_t linkageTruncated;
	uint16_t spare4;
	uint32_t linkageOffset;
	uint32_t linkageSize;
	char end_withLinkage[0];


	/* follow s above */
} CS_CodeDirectory
```

## 🤟🏻 Code Page Slot

애플의 Code Page Slot 정책의 핵심은 `Hash`다.
XNU Open Source를 분석해보면 굉장히 많고 긴 소스코드를 만날 수 있다.
비슷하게 애플이 다루고 있는 코드또한 굉장히 길고 많다. 이 코드에 모두 Hash 를 적용하는 것은 굉장히 비효율적이다. 그렇기에 애플이 사용한 방식이 Hash에 Hash를 적용한다.

코드 서명 분석

```bash
❯ codesign -d -vvvvvv /bin/ls                                                                                                                                                                                                                    ─╯
Executable=/bin/ls
Identifier=com.apple.ls
Format=Mach-O universal (x86_64 arm64e)
CodeDirectory v=20400 size=741 flags=0x0(none) hashes=18+2 location=embedded
Platform identifier=15
...
Signature size=4442
Authority=Software Signing
Authority=Apple Code Signing Certification Authority
Authority=Apple Root CA
Signed Time=Nov 12, 2023 at 13:42:54
Info.plist=not bound
TeamIdentifier=not set
Sealed Resources=none
Internal requirements count=1 size=60
```

> [!info] > </br>
> 이때 Code Directory가 나오는 이유는 Code Directory에 해시 페이지 크기가 저장되기 때문이다.
> </br>
> 이외에도 Hash type=sha256 size=32는 Code slot에 저장된다.

```bash
❯ ARCH=arm64e jtool2 --sig -v /bin/ls                                                                                                                                                                                                            ─╯
An embedded signature of 5287 bytes, with 3 blobs:
	Blob 0: Type: 0 @36: Code Directory (741 bytes)
		Version:     20400
		Flags:       none
		Platform Binary
		CodeLimit:   0x11150
		Identifier:  com.apple.ls (@0x58)
		...
```

```bash
 BINARY=/bin/ls
 SIZE=`stat -f "%z" $BINARY` ; PAGESIZE=`pagesize`
 PAGES=`expr $SIZE / $PAGESIZE`
```

```bash
❯ for i in `seq 0 $PAGES`; do \                                                                       ─╯
dd if=$BINARY of=/tmp/`basename $BINARY`.page.$i bs=$PAGESIZE count=1 skip=$i ;
done
1+0 records in
1+0 records out
16384 bytes transferred in 0.000410 secs (39960976 bytes/sec)
1+0 records in
1+0 records out
16384 bytes transferred in 0.000115 secs (142469565 bytes/sec)
1+0 records in
1+0 records out
16384 bytes transferred in 0.000121 secs (135404959 bytes/sec)
1+0 records in
1+0 records out
16384 bytes transferred in 0.000113 secs (144991150 bytes/sec)
1+0 records in
1+0 records out
16384 bytes transferred in 0.000522 secs (31386973 bytes/sec)
1+0 records in
1+0 records out
16384 bytes transferred in 0.000118 secs (138847458 bytes/sec)
1+0 records in
1+0 records out
16384 bytes transferred in 0.000132 secs (124121212 bytes/sec)
1+0 records in
1+0 records out
16384 bytes transferred in 0.000133 secs (123187970 bytes/sec)
1+0 records in
1+0 records out
16384 bytes transferred in 0.000824 secs (19883495 bytes/sec)
1+0 records in
1+0 records out
16384 bytes transferred in 0.000113 secs (144991150 bytes/sec)
1+0 records in
1+0 records out
16384 bytes transferred in 0.000472 secs (34711864 bytes/sec)
0+1 records in
0+1 records out
6896 bytes transferred in 0.000614 secs (11231270 bytes/sec)
```

```bash
openssl sha1 /tmp/ls*                                                                      ─╯
SHA1(/tmp/ls.page.0)=
SHA1(/tmp/ls.page.1)=
SHA1(/tmp/ls.page.10)=
SHA1(/tmp/ls.page.11)=
SHA1(/tmp/ls.page.2)=
SHA1(/tmp/ls.page.3)=
SHA1(/tmp/ls.page.4)=
SHA1(/tmp/ls.page.5)=
SHA1(/tmp/ls.page.6)=
SHA1(/tmp/ls.page.7)=
SHA1(/tmp/ls.page.8)=
SHA1(/tmp/ls.page.9)=
```

```bash
❯ ARCH=arm64e jtool2 --pages /bin/ls                                                                       ─╯
0x0-0x8000 __TEXT	(32768 bytes)
	0x3808-0x7420 __TEXT.__text	(15384 bytes)
	0x7420-0x7960 __TEXT.__auth_stubs	(1344 bytes)
	0x7960-0x7a34 __TEXT.__const	(212 bytes)
	0x7a34-0x7f28 __TEXT.__cstring	(1268 bytes)
	0x7f28-0x7ffc __TEXT.__unwind_info	(212 bytes)
0x8000-0xc000 __DATA_CONST	(16384 bytes)
	0x8000-0x82a0 __DATA_CONST.__auth_got	(672 bytes)
	0x82a0-0x82d0 __DATA_CONST.__got	(48 bytes)
	0x82d0-0x8538 __DATA_CONST.__const	(616 bytes)
0xc000-0x10000 __DATA	(16384 bytes)
	0xc000-0xc020 __DATA.__data	(32 bytes)
0x10000-0x15af0 __LINKEDIT	(23280 bytes)
	0x10000-0x10480 Binding info      (opcodes)	(1152 bytes)
	0x10480-0x104a0 Exports	(32 bytes)
	0x104a0-0x104f0 Function Starts	(80 bytes)
	0x104f0-0x10ab0 Symbol Table	(1472 bytes)
	0x10d68-0x11150 String Table	(1000 bytes)
	0x11150-0x15af0 Code Signature	(18848 bytes)
```

## ✌🏻✌🏻 특수 슬롯

> 특수 슬롯을 이용해서 코드 이외의 요소를 포함시킬 수 있다.

특징으로는 다음과 같다.

- 코드의 경우 0이상의 인덱스를 가지는데 특수 슬롯은 코드 이외의 요소를 다루기 때문에 음수의 인덱스를 가진다.

```
❯ ARCH=arm64e jtool2 --sig -v ./Mail | head -14                                                                                                                                                                                                  ─╯
An embedded signature of 60160 bytes, with 5 blobs:
	Blob 0: Type: 0 @52: Code Directory (42631 bytes)
		Version:     20400
		Flags:       none
		Platform Binary
		CodeLimit:   0x529680
		Identifier:  com.apple.mail (@0x58)
		...
```

위의 결과에서 hash type이 sha-256임을 확인할 수 있었다.

## 🖐🏻 애드 혹 서명

> 커널 수정을 위한 임시 서명

```bash
ARCH=arm64e JDEBUG=1 jtool2 --sign $BINARY                                                                                                                            ─╯
WTD: 0x88000000
Patching Linkedit by 70816 bytes
ADJUSTING BY 5280 bytes (FileSize: 5280 (i.e. to 70816), vmsize: 5280)
Signed to /tmp/ls
```

위와 같은 방식으로 adhoc을 이용할 수 있음.

## 🖐🏻☝🏻 코드 서명 플래그

코드 서명 플래그는 xnu/osfmk/kern/cs_blob.h 에 정의되어 있다.

```xnu/osfmk/kern/cs_blob.h
#define CS_VALID                    0x00000001  /* dynamically valid */
#define CS_ADHOC                    0x00000002  /* ad hoc signed */
#define CS_GET_TASK_ALLOW           0x00000004  /* has get-task-allow entitlement */
#define CS_INSTALLER                0x00000008  /* has installer entitlement */

#define CS_FORCED_LV                0x00000010  /* Library Validation required by Hardened System Policy */
#define CS_INVALID_ALLOWED          0x00000020  /* (macOS Only) Page invalidation allowed by task port policy */

#define CS_HARD                     0x00000100  /* don't load invalid pages */
#define CS_KILL                     0x00000200  /* kill process if it becomes invalid */
#define CS_CHECK_EXPIRATION         0x00000400  /* force expiration checking */
#define CS_RESTRICT                 0x00000800  /* tell dyld to treat restricted */

#define CS_ENFORCEMENT              0x00001000  /* require enforcement */
#define CS_REQUIRE_LV               0x00002000  /* require library validation */
#define CS_ENTITLEMENTS_VALIDATED   0x00004000  /* code signature permits restricted entitlements */
#define CS_NVRAM_UNRESTRICTED       0x00008000  /* has com.apple.rootless.restricted-nvram-variables.heritable entitlement */

#define CS_RUNTIME                  0x00010000  /* Apply hardened runtime policies */
#define CS_LINKER_SIGNED            0x00020000  /* Automatically signed by the linker */

#define CS_ALLOWED_MACHO            (CS_ADHOC | CS_HARD | CS_KILL | CS_CHECK_EXPIRATION | \
	                             CS_RESTRICT | CS_ENFORCEMENT | CS_REQUIRE_LV | CS_RUNTIME | CS_LINKER_SIGNED)

#define CS_EXEC_SET_HARD            0x00100000  /* set CS_HARD on any exec'ed process */
#define CS_EXEC_SET_KILL            0x00200000  /* set CS_KILL on any exec'ed process */
#define CS_EXEC_SET_ENFORCEMENT     0x00400000  /* set CS_ENFORCEMENT on any exec'ed process */
#define CS_EXEC_INHERIT_SIP         0x00800000  /* set CS_INSTALLER on any exec'ed process */

#define CS_KILLED                   0x01000000  /* was killed by kernel for invalidity */
#define CS_DYLD_PLATFORM            0x02000000  /* dyld used to load this is a platform binary */
#define CS_PLATFORM_BINARY          0x04000000  /* this is a platform binary */
#define CS_PLATFORM_PATH            0x08000000  /* platform binary by the fact of path (osx only) */

#define CS_DEBUGGED                 0x10000000  /* process is currently or has previously been debugged and allowed to run with invalid pages */
#define CS_SIGNED                   0x20000000  /* process has a signature (may have gone invalid) */
#define CS_DEV_CODE                 0x40000000  /* code is dev signed, cannot be loaded into prod signed code (will go away with rdar://problem/28322552) */
#define CS_DATAVAULT_CONTROLLER     0x80000000  /* has Data Vault controller entitlement */

#define CS_ENTITLEMENT_FLAGS        (CS_GET_TASK_ALLOW | CS_INSTALLER | CS_DATAVAULT_CONTROLLER | CS_NVRAM_UNRESTRICTED)
```

# 👉🏻 코드 서명 요구 사항

> 코드 서명이 요구하는 사항을 추가할 수 있도록 하는 확장된 추가 규칙을 의미.

# 👉🏻 Entitlement

> 특수 슬롯 -5 이용

```bash
❯ ARCH=arm64e jtool2 --ent /usr/libexec/neagent                                                                                                                         ─╯
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>com.apple.private.AppSSO.FetchNetworkCredentials</key>
	<true/>
	<key>com.apple.private.coreservices.canmaplsdatabase</key>
	<true/>
	<key>com.apple.private.neagent</key>
	<true/>
	<key>com.apple.private.skywalk.observe-stats</key>
	<true/>
</dict>
</plist>
```

위와 같이 확인할 수 있음.

> 이러한 방식으로 특정 동작에는 동작이 수행될 때 확인할 수 있는 자격이 부여될 수 있고, 요청자가 적절한 자격을 소요ㅠ하지 않는 경우에는 거부할 수 있다.

즉, 앱에서 권한을 요청하고, 그 요청에 대한 Entitlement를 가질 수 있다.
ex) com.apple.security.sandbox.conatiner-required 는 강제 샌드박스

# 👉🏻 Code-Signing Application

코드 서명은 `LC_CODE_SIGNATURE`를 파싱할 때 검증 또한 진행된다.
검증성공 -> 통합 버퍼 캐시에 로드.
