; #########################################################################

      .386
      .model flat, stdcall
      option casemap :none   ; case sensitive

; #########################################################################
      include \masm32\include\windows.inc
      include \masm32\include\user32.inc
      include \masm32\include\kernel32.inc
      include \masm32\include\comdlg32.inc
      
      includelib \masm32\lib\user32.lib
      includelib \masm32\lib\kernel32.lib
      includelib \masm32\lib\comdlg32.lib
      
; #########################################################################   
    .data
        buffer db 260 dup(0)
        ofn   OPENFILENAME <>
        FileBak db ".bak",0h
        FilterString db "All Files",0,"*.*",0h,0h
        OurTitle db "deSimpleUPXCryptor - Choose the Simple UPX crypted file to decrypt - coded by ap0x",0h
        strDoneTitle db "Success:",0h
        strDoneText db "[Done] File successfully decrypted by deSimpleUPXCryptor",0h
        strErrTitle db "Error:",0h
        strErrText db "[Error] File not found or Simple UPX Cryptor not detected!",0h
        hInstance     dd 0
    .data?
        FileName db 256h dup(?)
        FileNameBak db 256h dup(?)
        FileHWND dd ?
        FileMap dd ?
        FileMapRVA dd ?
        FileSize dd ?
	PE_Header dd ?
	PE_SectionNum dd ?
	PE_OEP dd ?
	PE_OEP_Offset dd ?
	UnpackedOEP dd ?
        NextDecrypt dd ?
        XORValue db ?
        XORCnt dd ?
        True_OEP_Offset db ?
        ConvertToFo dd ?
        ConvertedFo dd ?
	FirstLayer dd ?
        LastLayer dd ?
   .code

start:

;-----Readme.nfo-------------------------------------------------------------
;
;                    Property of Reversing Labs, inc.
;                   ----------------------------------
;   This  unpacker  for  Simple UPX cryptor is created by ap0x. This source
; code  is  for  educational purposes only so you may study how my unpacker
; works. But that is it, you DO NOT have the right to alter the code itself
; or compile it, but you may use it`s parts to create new programs. 
;        
;-----#EOF--------------------------------------------------------------------
;
; Last edited on: 12:41 PM 8/12/2005
;
;-----File mapping----------------------

        INVOKE GetModuleHandle, NULL
        MOV hInstance, EAX

        MOV ofn.lStructSize,SIZEOF ofn
        PUSH 0
        PUSH  ofn.hWndOwner
        PUSH hInstance
        PUSH  ofn.hInstance
        MOV  ofn.lpstrFilter, OFFSET FilterString
        MOV  ofn.lpstrFile, OFFSET buffer
        MOV  ofn.nMaxFile,512
        MOV  ofn.Flags, OFN_FILEMUSTEXIST or \
                        OFN_PATHMUSTEXIST or OFN_LONGNAMES or\
                        OFN_EXPLORER or OFN_HIDEREADONLY
        MOV  ofn.lpstrTitle, OFFSET OurTitle
        INVOKE GetOpenFileName, ADDR ofn

        INVOKE lstrcat,offset FileName,ofn.lpstrFile
        invoke lstrcat,offset FileNameBak,ofn.lpstrFile
	invoke lstrcat,offset FileNameBak,offset FileBak

        PUSH 1
        PUSH offset FileNameBak
        PUSH offset FileName
        CALL CopyFile

        PUSH 0h				;hTemplateFile
        PUSH 82h			;Hidden/Normal
        PUSH 3h				;OPEN_EXISTING
        PUSH 0h				;pSecurity
        PUSH 2h				;ShareMode = File Share Write
        PUSH 0C0000000h			;Access
        PUSH offset FileName
        CALL CreateFile
        CMP EAX,-1
        JE _not_found

        MOV EBX,offset FileHWND
        MOV DWORD PTR DS:[EBX],EAX

        PUSH 0
        PUSH EAX			;FileHWND
        CALL GetFileSize

        MOV EBX,offset FileSize
        MOV DWORD PTR DS:[EBX],EAX
      
        PUSH 0				;MapName
        PUSH EAX			;MinimumSizeLow = FileSize
        PUSH 0				;Maximum
        PUSH 4				;Protection
        PUSH 0			        ;pSecurity
        PUSH DWORD PTR DS:[FileHWND]    ;FileHWND
        CALL CreateFileMapping

        MOV EBX,offset FileMap
        MOV DWORD PTR DS:[EBX],EAX
          
        PUSH 0
        PUSH 0
        PUSH 0
        PUSH 2
        PUSH EAX
        CALL MapViewOfFile

        MOV EBX,offset FileMapRVA
        MOV DWORD PTR DS:[EBX],EAX

;-----Load elfanew----------------------

        MOV EBX, FileMapRVA
	MOV EAX, DWORD PTR[EBX+03Ch]
	MOV PE_Header, EAX

;-----Load Section Number---------------
         
	XOR ECX,ECX
	MOV CX, WORD PTR[EAX+EBX+06h]
	MOV PE_SectionNum, ECX

;-----Load OEP--------------------------

	MOV ECX, DWORD PTR[EBX+EAX+028h]
	MOV PE_OEP, ECX

;-----Seek OEP section------------------

        ;Seek section
        XOR EDX,EDX
        MOV EAX,PE_Header
        ADD EAX,0F8h
        PUSH EBP
        PUSH ESI
        PUSH EAX
        MOV ESI,DWORD PTR DS:[PE_SectionNum]
      _scan_sections:
        MOV CL,BYTE PTR DS:[EBX+EAX]
        INC EAX
        TEST CL,CL        
        JE _scan_sections
        MOV ECX,DWORD PTR DS:[PE_OEP]
        ADD EAX,0Bh
        MOV EDX,DWORD PTR DS:[EAX+EBX]
        SUB EAX,04h
        MOV EBP,DWORD PTR DS:[EAX+EBX]
        ADD EAX,04h
        ADD EDX,EBP
        CMP EDX,ECX
        JL _scan_next
        JG _scan_found
      _scan_next:
        SUB EAX,0Bh
        ADD EAX,27h
        DEC ESI
        TEST ESI,ESI
        JNE _scan_sections
        POP EAX
        POP ESI
        POP EBP
        JMP _not_found
      _scan_found:
        SUB EDX,EBP
        ADD EAX,8h
        SUB ECX,EDX
        XCHG EDX,ECX
        MOV ECX,DWORD PTR DS:[EAX+EBX]
        ADD ECX,EDX
        MOV DWORD PTR DS:[PE_OEP_Offset],ECX
        POP EAX
        POP ESI
        POP EBP
        ;End Seek

;-----Check UPX crypt version------------

	MOV EBX, FileMapRVA
	MOV EAX, PE_OEP_Offset
	MOV ECX, DWORD PTR[EBX+EAX]
	CMP CX, 0B860h	;Simple UPX Crypt
	JE _upx_simple_crypt
	JMP _unknown

;-----Simple UPX crypt--------------------

_upx_simple_crypt:

	MOV EBX, FileMapRVA
	MOV EAX, PE_OEP_Offset
        ADD EAX,2
	MOV ECX,DWORD PTR[EAX+EBX]
	MOV [NextDecrypt],ECX    
        MOV [ConvertToFo],ECX
        CALL _convert_va_2_of
	MOV ECX,[ConvertedFo]
	MOV [FirstLayer],ECX
	MOV [LastLayer],ECX

;-----Load XOR count---------------------

	MOV EBX, FileMapRVA
	MOV EAX, PE_OEP_Offset
	ADD EAX, 7
        XOR ECX,ECX
        MOV ECX,DWORD PTR[EAX+EBX]
        MOV [XORCnt],ECX

;-----Load XOR value---------------------

	MOV EBX, FileMapRVA
	MOV EAX, PE_OEP_Offset
	ADD EAX, 14
        MOV CL,BYTE PTR[EAX+EBX]
        MOV [XORValue],CL
       
;-----Decrypt all layers-----------------

     _sdc_all_layers:

        MOV EBX,[NextDecrypt]
        MOV [ConvertToFo],EBX
        CALL _convert_va_2_of
	MOV EAX,[ConvertedFo]
	MOV EBX, FileMapRVA
	MOV EDX,DWORD PTR[XORValue]
	XOR DH,DH
	MOV ECX,[XORCnt]
    _sdc_sc_ly_6:
	XOR BYTE PTR[EAX+EBX],DL
	INC EAX
	DEC ECX
	JNE _sdc_sc_ly_6
	CALL _s_load_next_layer_settings
	CMP [XORCnt],100h
	JG _sdc_last
	MOV EAX,[ConvertedFo]
        MOV [LastLayer],EAX
	JMP _sdc_all_layers

;-----Decrypt UPX body-------------------

    _sdc_last:
        MOV EBX,[NextDecrypt]
	MOV [UnpackedOEP],EBX
	INC [UnpackedOEP]
        MOV [ConvertToFo],EBX
        CALL _convert_va_2_of
	MOV EAX,[ConvertedFo]
	MOV EBX, FileMapRVA
	MOV EDX,DWORD PTR[XORValue]
	MOV ECX,[XORCnt]
	ADD ECX,1
    _sdc_sc_ly_6_f:
	XOR BYTE PTR[EAX+EBX],DL
	INC EAX
	DEC ECX
	JNE _sdc_sc_ly_6_f
	MOV BYTE PTR[EAX+EBX],0FFh

;-----Clear UPX Scrambler-----------------

	MOV EAX,[LastLayer]
	MOV EBX, FileMapRVA
	MOV ECX,[FirstLayer]
	SUB ECX,EAX
	MOV EAX,[LastLayer]	
	INC EAX
	TEST ECX,ECX
	JNE _scl_fl_
	MOV ECX,30h
    _scl_fl_:
	MOV BYTE PTR[EAX+EBX],0h
	INC EAX
	DEC ECX
	JNE _scl_fl_

	JMP _write_oep

;-----Write New OEP---------------------

_write_oep:

	SUB [UnpackedOEP],00400000h
	MOV ECX,[UnpackedOEP]
	MOV EAX,PE_Header
	MOV DWORD PTR[EBX+EAX+028h],ECX

;-----Unmap file------------------------

        PUSH DWORD PTR DS:[FileMapRVA]
        CALL UnmapViewOfFile

        PUSH DWORD PTR DS:[FileMap]
        CALL CloseHandle

        PUSH 0
        PUSH 0
        PUSH DWORD PTR DS:[FileSize]
        PUSH DWORD PTR DS:[FileHWND]
        CALL SetFilePointer

        PUSH DWORD PTR DS:[FileHWND]
        CALL SetEndOfFile

        PUSH DWORD PTR DS:[FileHWND]
        CALL CloseHandle

        PUSH 40h
        PUSH offset strDoneTitle
        PUSH offset strDoneText
        PUSH 0
        CALL MessageBox        
        JMP _done
        
_not_found:
_unknown:

        PUSH 30h
        PUSH offset strErrTitle
        PUSH offset strErrText
        PUSH 0
        CALL MessageBox
_done:
        invoke ExitProcess,eax

;------Ret to make Olly happy!----------

        RET

;------and deroko pissed :)-------------

    _convert_va_2_of:
        ;Seek section
        PUSHAD
        XOR EDX,EDX
        MOV EBX, FileMapRVA
        SUB [ConvertToFo],00400000h
        MOV EAX,PE_Header
        ADD EAX,0F8h
        MOV ESI,DWORD PTR DS:[PE_SectionNum]
      _scan_sections_:
        MOV CL,BYTE PTR DS:[EBX+EAX]
        INC EAX
        TEST CL,CL        
        JE _scan_sections_
        MOV ECX,DWORD PTR DS:[ConvertToFo]
        ADD EAX,0Bh
        MOV EDX,DWORD PTR DS:[EAX+EBX]
        SUB EAX,04h
        MOV EBP,DWORD PTR DS:[EAX+EBX]
        ADD EAX,04h
        ADD EDX,EBP
        CMP EDX,ECX
        JL _scan_next_
        JG _scan_found_
      _scan_next_:
        SUB EAX,0Bh
        ADD EAX,27h
        DEC ESI
        TEST ESI,ESI
        JNE _scan_sections_
        POP EAX
        POP ESI
        POP EBP
      _scan_found_:
        SUB EDX,EBP
        ADD EAX,8h
        SUB ECX,EDX
        XCHG EDX,ECX
        MOV ECX,DWORD PTR DS:[EAX+EBX]
        ADD ECX,EDX
        MOV DWORD PTR DS:[ConvertedFo],ECX
        POPAD
        ;End Seek
        RET

;---------------------------------------
;
; Simple UPX crypt load layer setting f.
;
;---------------------------------------

_s_load_next_layer_settings:
	PUSHAD
	MOV EBX, FileMapRVA
	MOV EAX, [ConvertedFo]
        ADD EAX, 3h
	MOV ECX,DWORD PTR[EAX+EBX]
	MOV [NextDecrypt],ECX    

	MOV EBX, FileMapRVA
	MOV EAX, [ConvertedFo]
	ADD EAX, 8h
        XOR ECX,ECX
        MOV ECX,DWORD PTR[EAX+EBX]
        MOV [XORCnt],ECX

	MOV EBX, FileMapRVA
	MOV EAX, [ConvertedFo]
	ADD EAX, 0Fh
        MOV CL,BYTE PTR[EAX+EBX]
        MOV [XORValue],CL
	POPAD
	RET
;---------------------------------------
end start