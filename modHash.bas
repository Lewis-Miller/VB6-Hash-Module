Option Explicit

'hashing functions MD5,SHA1,SHA256,SHA384,SHA512,HMAC_SHA256
'assumes Windows Vista or better
'some code gleaned and repurposed from dillante's excellent HS256 class
'https://www.vbforums.com/showthread.php?635398-VB6-HMAC-SHA-256-HMAC-SHA-1-Using-Crypto-API&highlight=sha256

Private Const ALG_CLASS_HASH As Long = (4 * 2 ^ 13)
Private Const ALG_CLASS_DATA_ENCRYPT As Long = (3 * 2 ^ 13)

Private Const ALG_TYPE_BLOCK As Long = (3 * 2 ^ 9)
Private Const ALG_TYPE_ANY As Long = 0

Private Const ALG_SID_MD5 As Long = 3
Private Const ALG_SID_RC2 As Long = 2
Private Const ALG_SID_SHA1 As Long = 4
Private Const ALG_SID_HMAC As Long = 9
Private Const ALG_SID_SHA_256 As Long = &HC
Private Const ALG_SID_SHA_384 As Long = &HD
Private Const ALG_SID_SHA_512 As Long = &HE

Private Const CALG_RC2 As Long = (ALG_CLASS_DATA_ENCRYPT Or ALG_TYPE_BLOCK Or ALG_SID_RC2)
Private Const CALG_HMAC As Long = (ALG_CLASS_HASH Or ALG_TYPE_ANY Or ALG_SID_HMAC)
Private Const CALG_MD5 As Long = ALG_CLASS_HASH Or ALG_TYPE_ANY Or ALG_SID_MD5
Private Const CALG_SHA1 As Long = (ALG_CLASS_HASH Or ALG_TYPE_ANY Or ALG_SID_SHA1)
Private Const CALG_SHA_256 As Long = ALG_CLASS_HASH Or ALG_TYPE_ANY Or ALG_SID_SHA_256
Private Const CALG_SHA_384 As Long = (ALG_CLASS_HASH Or ALG_TYPE_ANY Or ALG_SID_SHA_384)
Private Const CALG_SHA_512 As Long = (ALG_CLASS_HASH Or ALG_TYPE_ANY Or ALG_SID_SHA_512)


Private Const PROV_RSA_FULL As Long = 1
Private Const PROV_RSA_AES As Long = 24

Private Const MS_DEFAULT_PROVIDER As String = "Microsoft Base Cryptographic Provider v1.0"
Private Const MS_ENHANCED_RSA_AES_PROVIDER As String = "Microsoft Enhanced RSA and AES Cryptographic Provider"

Private Const HP_HASHVAL As Long = 2
Private Const HP_HASHSIZE As Long = 4
Private Const HP_HMAC_INFO As Long = 5

Private Const CRYPT_IPSEC_HMAC_KEY As Long = &H100&
Private Const CRYPT_MACHINE_KEYSET As Long = 32
Private Const CRYPT_VERIFYCONTEXT As Long = &HF0000000

Private Const PLAINTEXTKEYBLOB As Byte = &H8
Private Const CUR_BLOB_VERSION As Byte = &H2

Private Type HMAC_INFO
    HashAlgId As Long
    pbInnerString As Long
    cbInnerString As Long
    pbOuterString As Long
    cbOuterString As Long
End Type

Private Type BLOB_HEADER
    bType As Byte
    bVersion As Byte
    reserved As Integer
    aiKeyAlg As Long
End Type

Private Type Key_Blob
    hdr As BLOB_HEADER
    cbKeySize As Long
End Type

Private Declare Function CryptAcquireContext Lib "advapi32.dll" Alias "CryptAcquireContextA" (phProv As Long, ByVal pszContainer As String, ByVal pszProvider As String, ByVal dwProvType As Long, ByVal dwFlags As Long) As Long
Private Declare Function CryptCreateHash Lib "advapi32.dll" (ByVal hProv As Long, ByVal Algid As Long, ByVal hKey As Long, ByVal dwFlags As Long, phHash As Long) As Long
Private Declare Function CryptHashData Lib "advapi32.dll" (ByVal hHash As Long, pbData As Any, ByVal dwDataLen As Long, ByVal dwFlags As Long) As Long
Private Declare Function CryptGetHashParam Lib "advapi32.dll" (ByVal hHash As Long, ByVal dwParam As Long, pbData As Any, pdwDataLen As Long, ByVal dwFlags As Long) As Long
Private Declare Function CryptDestroyHash Lib "advapi32.dll" (ByVal hHash As Long) As Long
Private Declare Function CryptReleaseContext Lib "advapi32.dll" (ByVal hProv As Long, ByVal dwFlags As Long) As Long
Private Declare Function CryptDestroyKey Lib "Advapi32" (ByVal hKey As Long) As Long
Private Declare Function CryptImportKey Lib "Advapi32" (ByVal hProv As Long, ByVal pbData As Long, ByVal dwDataLen As Long, ByVal hPubKey As Long, ByVal dwFlags As Long, ByRef phKey As Long) As Long
Private Declare Function CryptSetHashParam Lib "Advapi32" (ByVal hHash As Long, ByVal dwParam As Long, ByRef pbData As HMAC_INFO, ByVal dwFlags As Long) As Long

Private Declare Sub CopyMemory Lib "kernel32" Alias "RtlMoveMemory" (ByVal Destination As Long, ByVal Source As Long, ByVal Length As Long)
Private Declare Function GetLastError Lib "kernel32" () As Long
Private Declare Function WideCharToMultiByte Lib "kernel32" ( _
                                             ByVal CodePage As Long, _
                                             ByVal dwFlags As Long, _
                                             ByVal lpWideCharStr As Long, _
                                             ByVal cchWideChar As Long, _
                                             ByVal lpMultiByteStr As Long, _
                                             ByVal cbMultiByte As Long, _
                                             ByVal lpDefaultChar As Long, _
                                             ByVal lpUsedDefaultChar As Long) As Long



'use these to specify your desired hash algorithym
'hmac-sha256 requires a key
#If False Then
    Dim HASH_MD5, HASH_SHA1, HASH_SHA256, HASH_SHA384, HASH_SHA512, HASH_HMACSHA256, HASH_HMACSHA384, HASH_HMACSHA512
#End If
Public Enum HASH_ALGO
    HASH_MD5 = CALG_MD5
    HASH_SHA1 = CALG_SHA1
    HASH_SHA256 = CALG_SHA_256
    HASH_SHA384 = CALG_SHA_384
    HASH_SHA512 = CALG_SHA_512
    HASH_HMACSHA256 = CALG_HMAC  ' Special

    'experimental
    HASH_HMACSHA384 = CALG_HMAC Or CALG_SHA_384
    HASH_HMACSHA512 = CALG_HMAC Or CALG_SHA_512
End Enum

'the main compute hashing engine, takes in byte arrays spits out a byte array hash
Public Function ComputeHash(ByRef Data() As Byte, ByVal ALGO As HASH_ALGO, ByRef Key() As Byte) As Byte()

    Dim hProv As Long, hKey As Long, hHash As Long
    Dim hashSize As Long, hashLen As Long
    Dim KeyBlob As Key_Blob, keyBytes() As Byte
    Dim Ret As Long, X As Long
    Dim hashBytes() As Byte
    Dim hmacInfo As HMAC_INFO

    If IsArrayEmpty(Data) Then Exit Function

    ' Pick provider based on algo
    If ALGO = HASH_MD5 Then
        Ret = CryptAcquireContext(hProv, vbNullString, MS_DEFAULT_PROVIDER, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)
    Else
        If ALGO = HASH_HMACSHA256 And IsArrayEmpty(Key) = True Then Exit Function
        Ret = CryptAcquireContext(hProv, vbNullString, MS_ENHANCED_RSA_AES_PROVIDER, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)
    End If

    If Ret = 0 Then GoTo Cleanup

    If ALGO = HASH_HMACSHA256 Or ALGO = HASH_HMACSHA384 Or ALGO = HASH_HMACSHA512 Then
        ' Build plaintext key blob
        With KeyBlob.hdr
            .bType = PLAINTEXTKEYBLOB
            .bVersion = CUR_BLOB_VERSION
            .aiKeyAlg = CALG_RC2
        End With
        KeyBlob.cbKeySize = UBound(Key) - LBound(Key) + 1

        ReDim keyBytes(LenB(KeyBlob) + KeyBlob.cbKeySize - 1)
        CopyMemory VarPtr(keyBytes(0)), VarPtr(KeyBlob), LenB(KeyBlob)
        CopyMemory VarPtr(keyBytes(LenB(KeyBlob))), VarPtr(Key(LBound(Key))), KeyBlob.cbKeySize

        Ret = CryptImportKey(hProv, VarPtr(keyBytes(0)), UBound(keyBytes) + 1, 0, CRYPT_IPSEC_HMAC_KEY, hKey)
        If Ret = 0 Then GoTo Cleanup

        Ret = CryptCreateHash(hProv, CALG_HMAC, hKey, 0, hHash)
        If Ret = 0 Then GoTo Cleanup

        If ALGO = HASH_HMACSHA256 Then
            hmacInfo.HashAlgId = CALG_SHA_256
        ElseIf ALGO = HASH_HMACSHA384 Then
            hmacInfo.HashAlgId = CALG_SHA_384
        ElseIf ALGO = HASH_HMACSHA512 Then
            hmacInfo.HashAlgId = CALG_SHA_512
        End If
        Ret = CryptSetHashParam(hHash, HP_HMAC_INFO, hmacInfo, 0)
    Else
        ' Plain hash (MD5/SHA256/SHA1)
        Ret = CryptCreateHash(hProv, CLng(ALGO), 0&, 0&, hHash)
    End If
    If Ret = 0 Then GoTo Cleanup

    Ret = CryptHashData(hHash, Data(0), UBound(Data) + 1, 0)
    If Ret = 0 Then GoTo Cleanup

    hashLen = 4
    Ret = CryptGetHashParam(hHash, HP_HASHSIZE, hashSize, hashLen, 0)
    If Ret = 0 Then GoTo Cleanup

    ReDim hashBytes(hashSize - 1)
    Ret = CryptGetHashParam(hHash, HP_HASHVAL, hashBytes(0), hashSize, 0)
    If Ret = 0 Then GoTo Cleanup

    ComputeHash = hashBytes

Cleanup:
    If Ret = 0 Then
        Debug.Print "Error in ComputeHash()! &H" & Hex$(GetLastError)
    End If
    If hHash <> 0 Then CryptDestroyHash hHash
    If hKey <> 0 Then CryptDestroyKey hKey
    If hProv <> 0 Then CryptReleaseContext hProv, 0
End Function


'high level functions for files, strings
'you only need to pass a key if its hmac_sha256
Function HashFile(ByVal strFilePath As String, ByVal HASH_TYPE As HASH_ALGO, Optional ByVal HashKey As String) As String
    Dim fNum As Integer
    Dim fileBytes() As Byte
    Dim keyBytes() As Byte

    If Len(strFilePath) = 0 Then
        Exit Function
    End If

    On Error GoTo Error_Handler
    fNum = FreeFile
    Open strFilePath For Binary As fNum
    If LOF(fNum) > 0 Then
        ReDim fileBytes(LOF(fNum) - 1) As Byte
        Get #fNum, , fileBytes
    Else
        GoTo Error_Handler
    End If
    Close fNum

    If HASH_TYPE = HASH_HMACSHA256 Or _
       HASH_TYPE = HASH_HMACSHA384 Or _
       HASH_TYPE = HASH_HMACSHA512 Then

        If Len(HashKey) < 2 Then
            Debug.Print "HashFile() Error: Key must be longer than 1 character."
            GoTo Error_Handler
        End If

        keyBytes = StringToUTF8(HashKey)
    Else
        ReDim keyBytes(0)
    End If

    HashFile = BytesToHex(ComputeHash(fileBytes, HASH_TYPE, keyBytes))
    On Error GoTo 0

    Exit Function

Error_Handler:
    'MsgBox "HashFile() Error! " & Err.Number & " - " & Err.Description
    If fNum > 0 Then
        Close #fNum
    End If

    On Error GoTo 0
End Function

Function HashString(ByVal strInput As String, ByVal HASH_TYPE As HASH_ALGO, Optional ByVal HashKey As String) As String
    Dim stringBytes() As Byte
    Dim keyBytes() As Byte

    If Len(strInput) = 0 Then
        Exit Function
    End If

    stringBytes = StringToUTF8(strInput)

    If HASH_TYPE = HASH_HMACSHA256 Or _
       HASH_TYPE = HASH_HMACSHA384 Or _
       HASH_TYPE = HASH_HMACSHA512 Then

        If Len(HashKey) < 2 Then
            Debug.Print "HashString() Error: Key must be longer than 1 character."
            Exit Function
        End If

        keyBytes = StringToUTF8(HashKey)
    End If

    HashString = BytesToHex(ComputeHash(stringBytes, HASH_TYPE, keyBytes))

End Function

'helper function to check arrays, ugly but it works
Private Function IsArrayEmpty(ByRef Arr() As Byte) As Boolean
    On Error Resume Next
    If (UBound(Arr) < 0) Then
        IsArrayEmpty = True
    End If
    IsArrayEmpty = (Err.Number > 0)
    Err.Clear
    On Error GoTo 0
End Function


Public Function StringToUTF8(ByVal sText As String, Optional ByVal CodePage As Long = 65001) As Byte()

    Dim Bytes() As Byte
    Dim cbNeeded As Long
    Dim cbWritten As Long

    If Len(sText) = 0 Then Exit Function

    On Error GoTo Error_Handler
    ' First pass: get required size
    cbNeeded = WideCharToMultiByte(CodePage, 0, StrPtr(sText), Len(sText), 0, 0, 0, 0)
    If cbNeeded = 0 Then Exit Function

    ' Allocate exactly what we need
    ReDim Bytes(cbNeeded - 1)

    ' Second pass: convert
    cbWritten = WideCharToMultiByte(CodePage, 0, StrPtr(sText), Len(sText), VarPtr(Bytes(0)), cbNeeded, 0, 0)
    If cbWritten = 0 Then Exit Function

    ' Trim if needed (shouldn't be, but safety...)
    If cbWritten < cbNeeded Then ReDim Preserve Bytes(cbWritten - 1)

    StringToUTF8 = Bytes
    On Error GoTo 0
    Exit Function

Error_Handler:
    ' Debug.Print "UTF-8 conversion failed: " & Err.Number & " - " & Err.Description
    On Error GoTo 0
End Function


' Convert byte array to hex string (with optional separator between bytes)
Function BytesToHex(Bytes() As Byte, Optional ByVal Separator As String = "") As String
    Dim X As Long
    Dim Pos As Long    ' Current position in output string (1-based)
    Dim Size As Long
    Dim SepLen As Long

    If IsArrayEmpty(Bytes) Then Exit Function

    Size = UBound(Bytes) + 1
    SepLen = Len(Separator)

    ' Pre-allocate exact length: bytes * 2 + (bytes - 1) * separator length
    BytesToHex = Space$(Size * 2 + (Size - 1) * SepLen)

    Pos = 1
    For X = LBound(Bytes) To UBound(Bytes)
        ' Write two hex chars
        Mid$(BytesToHex, Pos, 2) = Right$("0" & Hex$(Bytes(X)), 2)
        Pos = Pos + 2

        ' Add separator if not the last byte
        If X < UBound(Bytes) And SepLen > 0 Then
            Mid$(BytesToHex, Pos, SepLen) = Separator
            Pos = Pos + SepLen
        End If
    Next X
End Function



