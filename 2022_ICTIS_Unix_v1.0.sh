#!/bin/sh

OS=`uname`

if [ $OS = Linux ]
	then
		#alias echo='echo -e'
		IP=`hostname -I | sed 's/ //g'`
fi

if [ $OS = SunOS ]
	then
		IP=`ifconfig -a | grep broadcast | cut -f 2 -d ' '`
fi

LANG=C
export LANG

alias ls=ls

CREATE_FILE=Linux_server_script_result.txt
CHECK_FILE=`ls ./"$CREATE_FILE" 2>/dev/null | wc -l`

perm_check() {
    unset FUNC_FILE
    unset PERM
    unset NUM
    unset PERM_CHECK
    unset OWNER_FUNC_fRESULT
    unset PERM_FUNC_RESULT
    unset VALUE

    FUNC_FILE=$1
    PERM=`ls -al $FUNC_FILE | awk '{print $1}'`
    OWNER_FUNC_RESULT=`ls -al $FUNC_FILE | awk '{print $3}'`
    PERM=`expr "$PERM" : '.\(.*\)' | sed -e "s/-/A/g"`;

    while :
    do
        NUM=`echo $PERM | awk '{print length($0)}'`

        if [ $NUM -eq 0 ]
            then
                break
        fi

        PERM_CHECK=`expr "$PERM" : '\(...\).*'`
        PERM=`expr "$PERM" : '...\(.*\)'`

        if [ "$PERM_CHECK" = "rwx" -o "$PERM_CHECK" = "rws" -o "$PERM_CHECK" = "rwS" ]
            then
                VALUE="7"
        fi

        if [ "$PERM_CHECK" = "rwA" ]
            then
                VALUE="6"
        fi

        if [ "$PERM_CHECK" = "rAx" -o "$PERM_CHECK" = "rAs" -o "$PERM_CHECK" = "rAS" ]
            then
                VALUE="5"
        fi

        if [ "$PERM_CHECK" = "rAA" ]
            then
                VALUE="4"
        fi

        if [ "$PERM_CHECK" = "Awx" -o "$PERM_CHECK" = "Aws" -o "$PERM_CHECK" = "AwS" ]
            then
                VALUE="3"
        fi

        if [ "$PERM_CHECK" = "AwA" ]
            then
                VALUE="2"
        fi

        if [ "$PERM_CHECK" = "AAx" -o "$PERM_CHECK" = "AAs" -o "$PERM_CHECK" = "AAS" ]
            then
                VALUE="1"
        fi

        if [ "$PERM_CHECK" = "AAA" ]
            then
                VALUE="0"
        fi

        PERM_FUNC_RESULT=$PERM_FUNC_RESULT" "$VALUE
    done

    PERM_FUNC_RESULT=$PERM_FUNC_RESULT" "$OWNER_FUNC_RESULT

    return
}

perm_check_dir() {
    unset FUNC_FILE
    unset PERM
    unset OWNER_FUNC_RESULT
    unset NUM
    unset PERM_CHECK
    unset PERM_FUNC_RESULT
    unset VALUE

    FUNC_FILE=$1

    PERM=`ls -alLd $FUNC_FILE | awk '{print $1}'`
    OWNER_FUNC_RESULT=`ls -alLd $FUNC_FILE | awk '{print $3}'`
    PERM=`expr "$PERM" : '.\(.*\)' | sed -e "s/-/A/g"` 

    while :
    do
        NUM=`echo $PERM | awk '{print length($0)}'`

        if [ $NUM -eq 0 ]
            then
                break
        fi

        PERM_CHECK=`expr "$PERM" : '\(...\).*'`
        PERM=`expr "$PERM" : '...\(.*\)'` 	

        if [ "$PERM_CHECK" = "rwx" -o "$PERM_CHECK" = "rws" -o "$PERM_CHECK" = "rwS" ]
            then
                VALUE="7"
        fi

        if [ "$PERM_CHECK" = "rwA" ]
            then
                VALUE="6"
        fi

        if [ "$PERM_CHECK" = "rAx" -o "$PERM_CHECK" = "rAs" -o "$PERM_CHECK" = "rAS" ]
            then
                VALUE="5"
        fi

        if [ "$PERM_CHECK" = "rAA" ]
            then
                VALUE="4"
        fi

        if [ "$PERM_CHECK" = "Awx" -o "$PERM_CHECK" = "Aws" -o "$PERM_CHECK" = "AwS" ]
            then
                VALUE="3"
        fi

        if [ "$PERM_CHECK" = "AwA" ]
            then
                VALUE="2"
        fi

        if [ "$PERM_CHECK" = "AAx" -o "$PERM_CHECK" = "AAs" -o "$PERM_CHECK" = "AAS" ]
            then
                VALUE="1"
        fi

        if [ "$PERM_CHECK" = "AAA" ]
            then
                VALUE="0"
        fi

        PERM_FUNC_RESULT=$PERM_FUNC_RESULT" "$VALUE
    done

    PERM_FUNC_RESULT=$PERM_FUNC_RESULT" "$OWNER_FUNC_RESULT

    return
}
echo " "
echo " "
echo > $CREATE_FILE 2>&1
echo " "
echo "----------------------------------------------------------------------------------------------------"
echo "---------------------------------------   진단 전 주의사항    --------------------------------------"
echo "---------------------------   반드시 Super 유저 권한에서 진단을 시작해야 합니다!   -----------------"
echo "----------------------------------------------------------------------------------------------------"
echo " "
echo " "
echo " "
echo "                      ==========================================================="
echo "                      ==============   UNIX/Linux Security Check   =============="
echo "                      ==========================================================="
echo " "
echo " "
echo "==========================" >> $CREATE_FILE 2>&1
echo "UNIX/Linux Security Check" >> $CREATE_FILE 2>&1
echo "==========================" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

echo "****************************************************************************************************"
echo "****************************************   INFO_CHKSTART   *****************************************"
echo "****************************************************************************************************"
echo " "
echo " "

#echo " " >> $CREATE_FILE 2>&1
#echo " " >> $CREATE_FILE 2>&1
#echo "****************************************************************************************************" >> $CREATE_FILE 2>&1
#echo "****************************************   INFO_CHKSTART   *****************************************" >> $CREATE_FILE 2>&1
#echo "****************************************************************************************************" >> $CREATE_FILE 2>&1
#echo " " >> $CREATE_FILE 2>&1
#echo " " >> $CREATE_FILE 2>&1
#echo " " >> $CREATE_FILE 2>&1

echo "------------------------------------------   Start Time   ------------------------------------------"
echo " "
date
echo " "
echo "----------------------------------------------------------------------------------------------------"
echo " "
echo " "
echo " "

echo "------------------------------------------   Start Time   ------------------------------------------" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
date >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo "----------------------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

echo "                      ==========================================================="
echo "                      ===========   System Information Query Start   ============"
echo "                      ==========================================================="
echo " "
echo " "
echo " "

#echo "                      ===========================================================" >> $CREATE_FILE 2>&1
#echo "                      ===========   System Information Query Start   ===========" >> $CREATE_FILE 2>&1
#echo "                      ===========================================================" >> $CREATE_FILE 2>&1
#echo " " >> $CREATE_FILE 2>&1
#echo " " >> $CREATE_FILE 2>&1
#echo " " >> $CREATE_FILE 2>&1

echo "--------------------------------------   Kernel Information   --------------------------------------"
echo " "
KERNEL=`uname -a`
echo $KERNEL
echo " "
echo "----------------------------------------------------------------------------------------------------"
echo " "

#echo "--------------------------------------   Kernel Information   --------------------------------------" >> $CREATE_FILE 2>&1
#echo " " >> $CREATE_FILE 2>&1
#uname -a >> $CREATE_FILE 2>&1
#echo " " >> $CREATE_FILE 2>&1
#echo "----------------------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
#echo " " >> $CREATE_FILE 2>&1

echo "----------------------------------------   IP Information   ----------------------------------------"
echo " "
IFCONFIG=`ifconfig -a`
echo $IFCONFIG
echo " "
echo "----------------------------------------------------------------------------------------------------"
echo " "

#echo "----------------------------------------   IP Information   ----------------------------------------" >> $CREATE_FILE 2>&1
#echo " " >> $CREATE_FILE 2>&1
#ifconfig -a >> $CREATE_FILE 2>&1
#echo " " >> $CREATE_FILE 2>&1
#echo "----------------------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
#echo " " >> $CREATE_FILE 2>&1

echo "----------------------------------------   Network Status   ----------------------------------------"
echo " "
NETSTAT=`netstat -an | egrep -i "LISTEN|ESTABLISHED"`
echo $NETSTAT
echo " "
echo "----------------------------------------------------------------------------------------------------"
echo " "

#echo "----------------------------------------   Network Status   ----------------------------------------" >> $CREATE_FILE 2>&1
#echo " " >> $CREATE_FILE 2>&1
#netstat -an | egrep -i "LISTEN|ESTABLISHED" >> $CREATE_FILE 2>&1
#echo " " >> $CREATE_FILE 2>&1
#echo "----------------------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
#echo " " >> $CREATE_FILE 2>&1

echo "-------------------------------------   Routing Information   --------------------------------------"
echo " "
NETSTATR=`netstat -rn`
echo $NETSTATR
echo " "
echo "----------------------------------------------------------------------------------------------------"
echo " "

#echo "-------------------------------------   Routing Information   --------------------------------------" >> $CREATE_FILE 2>&1
#echo " " >> $CREATE_FILE 2>&1
#netstat -rn >> $CREATE_FILE 2>&1
#echo " " >> $CREATE_FILE 2>&1
#echo "----------------------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
#echo " " >> $CREATE_FILE 2>&1

echo "---------------------------------------   Process Status   -----------------------------------------"
echo " "
PS=`ps -ef`
echo $PS
echo " "
echo "----------------------------------------------------------------------------------------------------"
echo " "

#echo "---------------------------------------   Process Status   -----------------------------------------" >> $CREATE_FILE 2>&1
#echo " " >> $CREATE_FILE 2>&1
#ps -ef >> $CREATE_FILE 2>&1
#echo " " >> $CREATE_FILE 2>&1
#echo "----------------------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
#echo " " >> $CREATE_FILE 2>&1

echo "------------------------------------------   User Env   --------------------------------------------"
echo " "
UE=`env`
echo $UE
echo " "
echo "----------------------------------------------------------------------------------------------------"
echo " "
echo " "
echo " "

#echo "------------------------------------------   User Env   --------------------------------------------" >> $CREATE_FILE 2>&1
#echo " " >> $CREATE_FILE 2>&1
#env >> $CREATE_FILE 2>&1
#echo " " >> $CREATE_FILE 2>&1
#echo "----------------------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
#echo " " >> $CREATE_FILE 2>&1


echo "                    ==========================================================="
echo "                    ============   System Information Query End   ============="
echo "                    ==========================================================="
echo " "
echo " "

#echo "                    ===========================================================" >> $CREATE_FILE 2>&1
#echo "                    ============   System Information Query End   =============" >> $CREATE_FILE 2>&1
#echo "                    ===========================================================" >> $CREATE_FILE 2>&1
#echo " " >> $CREATE_FILE 2>&1
#echo " " >> $CREATE_FILE 2>&1

echo "****************************************************************************************************"
echo "*****************************************   INFO_CHKEND   ******************************************"
echo "****************************************************************************************************"
echo " "
echo " "

#echo "****************************************************************************************************" >> $CREATE_FILE 2>&1
#echo "*****************************************   INFO_CHKEND   ******************************************" >> $CREATE_FILE 2>&1
#echo "****************************************************************************************************" >> $CREATE_FILE 2>&1
#echo " " >> $CREATE_FILE 2>&1
#echo " " >> $CREATE_FILE 2>&1

echo ">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
echo "<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<"
echo " "
echo " "
#echo ">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>" >> $CREATE_FILE 2>&1
#echo "<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<" >> $CREATE_FILE 2>&1
#echo " " >> $CREATE_FILE 2>&1
#echo " " >> $CREATE_FILE 2>&1

echo "                    ==========================================================="
echo "                    ================   Security Check START   ================="
echo "                    ==========================================================="
echo " "
echo " "

echo "====================" >> $CREATE_FILE 2>&1
echo "Security Check START" >> $CREATE_FILE 2>&1
echo "====================" >> $CREATE_FILE 2>&1
echo >> $CREATE_FILE 2>&1
echo >> $CREATE_FILE 2>&1

#echo "===========================================================" >> $CREATE_FILE 2>&1
#echo "===========================================================" >> $CREATE_FILE 2>&1
#echo >> $CREATE_FILE 2>&1

	
echo "[U-01] root 계정 원격 접속 제한"  
	echo "[U-01] root 계정 원격 접속 제한"  >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
	echo "[START]"  >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
	echo "TELNET 판단기준 : TELNET을 사용하지 않거나 Root 직접 접속 차단 설정" >> $CREATE_FILE 2>&1	
			
	case $OS in
		SunOS)
			echo "1. 현황 : ps -ef | grep telnet " >> $CREATE_FILE 2>&1	
			ps -ef | grep 'telnet' | grep -v 'grep' >> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1		
			echo "2. 현황 : /etc/default/login 파일의 CONSOLE=/dev/console 확인(주석되어있으면 취약)" >> $CREATE_FILE 2>&1	
			cat /etc/default/login | grep CONSOLE | grep -v \# >> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1
			;;
		Linux) ##############################수정.순서변경
			echo "판단기준 참고 : auth required pam_securetty.so (pam_faillock.so) 설정 및 pts/x 미설정시 양호" >> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1
			echo "1. pam_securetty.so 설정 및 pts/x 설정 확인" >> $CREATE_FILE 2>&1
			echo "1-1. grep -E "pam_securetty" /etc/pam.d/login" >> $CREATE_FILE 2>&1
			grep -E "pam_securetty" /etc/pam.d/login | grep -v '' >> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1
			echo "1-2. grep -E "pts" /etc/securetty" >> $CREATE_FILE 2>&1
			grep -E "pts" /etc/securetty | grep -v '^#' >> $CREATE_FILE 2>&1
			
			echo " " >> $CREATE_FILE 2>&1
			echo "2. 현황 : /etc/pam.d/login 상세 내용" >> $CREATE_FILE 2>&1
			cat /etc/pam.d/login | grep -v '^#' >> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1
			echo "3. 현황 : /etc/securetty 상세 내용"  >> $CREATE_FILE 2>&1
			cat /etc/securetty | grep -v '^#' >> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1
			;;
		AIX)
			echo "1. 현황 : ps -ef | grep telnet " >> $CREATE_FILE 2>&1	
			ps -ef | grep 'telnet' | grep -v 'grep' >> $CREATE_FILE 2>&1
			echo "2. 현황 : cat /etc/security/user 파일의 rlogin = false일때 양호" >> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1
			cat /etc/security/user >> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1		
			;;	
		HP-UX)
			echo "1. 현황 : ps -ef | grep telnet " >> $CREATE_FILE 2>&1	
			ps -ef | grep 'telnet' | grep -v 'grep' >> $CREATE_FILE 2>&1
			echo "2. 현황 : /etc/securetty 파일의 console 주석 미처리시 양호" >> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1
			cat /etc/securetty >> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1
			;;		
	esac
			
			echo "판단기준 : SSH를 사용하지 않거나, SSH의 설정 파일 중 PermitRootLogin값을 no로 설정시 양호" >> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1
			echo "1. 서비스 현황" >> $CREATE_FILE 2>&1	
			ps -ef | grep 'ssh' | grep -v 'grep' >> $CREATE_FILE 2>&1
			
			ServiceDIR="/etc/sshd_config /etc/ssh/sshd_config /usr/local/etc/sshd_config /usr/local/sshd/etc/sshd_config /usr/local/ssh/etc/sshd_config"
			for file in $ServiceDIR #/etc/ssh/sshd_config 우분투18
			do
				echo " " >> $CREATE_FILE 2>&1
				echo "2. 현황 : $file 설정 파일 (결과 없을시 PermitRootLogin 미설정)" >> $CREATE_FILE 2>&1	
				cat $file | grep PermitRootLogin | grep -v '^#'	>> $CREATE_FILE 2>&1
			done
	echo " " >> $CREATE_FILE 2>&1
	echo "[END]" >> $CREATE_FILE 2>&1

echo "[U-02] 패스워드 복잡성 설정"
	echo "[U-02] 패스워드 복잡성 설정" >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
	echo "[START]"  >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
	echo "판단기준 : 영문,숫자,특수문자 조합하여 2종류 조합시 10자리 이상, 3종류 조합시 8자리 이상 설정 (공공기관 9자리 이상)" >> $CREATE_FILE 2>&1
	case $OS in
		SunOS)	
			echo "*****************************************" >> $CREATE_FILE 2>&1
			echo "1. PASSLENGTH(패스워드 최소길이) 8자리 이상 설정" >> $CREATE_FILE 2>&1
			echo "2. MINDIGHT(숫자최소 갯수) 1이상 설정" >> $CREATE_FILE 2>&1
			echo "3. MINUPPER(알파벳 대문자 최소 갯수) 1이상 설정" >> $CREATE_FILE 2>&1
			echo "4. MINLOWER(알파벳 소문자 최소 갯수) 1이상 설정" >> $CREATE_FILE 2>&1
			echo "5. MINSPECIAL(특수문자 최소 갯수) 1이상 설정" >> $CREATE_FILE 2>&1
			echo "*****************************************" >> $CREATE_FILE 2>&1
			echo "현황 : /etc/default/passwd" >> $CREATE_FILE 2>&1	
			cat /etc/default/passwd  >> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1
			echo "현황 : /etc/security/policy.conf"  >> $CREATE_FILE 2>&1
			cat /etc/security/policy.conf >> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1
			;;
		Linux)
			echo "******************************************************" >> $CREATE_FILE 2>&1
			echo "1. Minlen(패스워드 최소길이) 8자리 이상 설정" >> $CREATE_FILE 2>&1
			echo "2. Ucredit(숫자 입력 겂증값) -1이하 설정" >> $CREATE_FILE 2>&1
			echo "3. Dcredit(대문자 입력 겂증값) -1이하 설정" >> $CREATE_FILE 2>&1
			echo "4. Ocredit(소문자 입력 검증값) -1이하 설정" >> $CREATE_FILE 2>&1
			echo "5. Lcredit(특수문자 입력 검증값) -1이하 설정" >> $CREATE_FILE 2>&1
			echo "******************************************************" >> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1
			echo "1. 현황 : /etc/pam.d/system-auth 상세 내용" >> $CREATE_FILE 2>&1
			cat /etc/pam.d/system-auth | grep -v '^#' >> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1
			echo "2. 현황 : /etc/pam.d/common-password 상세 내용" >> $CREATE_FILE 2>&1
			cat /etc/pam.d/common-password | grep -v '^#' >> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1
			
			echo "3. 현황 : /etc/security/pwquality.conf 상세 내용" >> $CREATE_FILE 2>&1
			cat /etc/security/pwquality.conf  | grep -v '^#' >> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1
			echo "4. 현황 : /etc/login.defs 상세 내용" >> $CREATE_FILE 2>&1
			cat /etc/login.defs  | grep -v '^#' >> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1
			;;
		AIX)
			echo "현황 : /etc/security/user" >> $CREATE_FILE 2>&1
			cat /etc/security/user >> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1
			;;
		HP-UX)
			echo "현황 : /tcb/files/auth/system/default" >> $CREATE_FILE 2>&1
			cat /tcb/files/auth/system/default >> $CREATE_FILE 2>&1
			echo "현황 : /etc/default/security" >> $CREATE_FILE 2>&1
			cat /etc/default/security >> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1
			;;
	esac
	echo " " >> $CREATE_FILE 2>&1
	echo "[END]" >> $CREATE_FILE 2>&1


echo "[U-03] 계정 잠금 임계값 설정"
	echo "[U-03] 계정 잠금 임계값 설정" >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
	echo "[START]"  >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
	echo "판단기준 : 계정 임계값이 5이하의 값으로 설정" >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
	case $OS in
		SunOS)
			echo "***************************************************************************************" >> $CREATE_FILE 2>&1
			echo "1. /etc/default/login 파일 내 RETRIES(계정잠금 임계)값이 5인지 확인" >> $CREATE_FILE 2>&1
			echo "2. /etc/security/policy.conf 파일 내 LOCK_AFTER_RETRIES(계정잠금)값이 YES인지 확인" >> $CREATE_FILE 2>&1
			echo "***************************************************************************************" >> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1
			echo "1. 현황 : /etc/default/login" >> $CREATE_FILE 2>&1
			cat /etc/default/login | grep RETRIES>> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1
			echo "2. 현황 : /etc/security/policy.conf" >> $CREATE_FILE 2>&1
			cat /etc/security/policy.conf | grep RETRIES >> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1
			;;
		Linux)
			echo "****************************************************************************************************************" >> $CREATE_FILE 2>&1
			echo "1. auth required /lib/security/pam_tally.so deny=5 unlock_time=120 no_magic_root 확인" >> $CREATE_FILE 2>&1
			echo "2. account required /lib/security/pam_tally.so no_magic_root reset 확인" >> $CREATE_FILE 2>&1
			echo "3. (CentOs 8 이상) account required pam_faillock.so preauth silent audit deny=5 unlock_time=120 확인" >> $CREATE_FILE 2>&1
			echo "****************************************************************************************************************" >> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1
			echo "1. 현황 : /etc/pam.d/system-auth 상세 내용" >> $CREATE_FILE 2>&1
			cat /etc/pam.d/system-auth | grep -v '^#'  >> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1
			echo "2. 현황 : /etc/pam.d/common-auth 상세 내용" >> $CREATE_FILE 2>&1
			cat /etc/pam.d/common-auth | grep -v '^#'  >> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1
			;;
		AIX)
			echo "판단기준 : loginretries=5 확인" >> $CREATE_FILE 2>&1
			echo "현황 : /etc/security/user" >> $CREATE_FILE 2>&1
			cat /etc/security/user >> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1
			;;
		HP-UX)
			echo "판단기준 : maxtries=5 확인" >> $CREATE_FILE 2>&1
			echo "현황 : HP-UX 11.v2 이하 일경우 /tcb/files/auth/system/default" >> $CREATE_FILE 2>&1
			cat /tcb/files/auth/system/default >> $CREATE_FILE 2>&1
			echo "현황 : HP-UX 11.v3 이상 일경우 /etc/default/security의 AUTH_MAXTRIES 확인" >> $CREATE_FILE 2>&1
			cat /etc/default/security >> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1
			;;
	esac
	echo " " >> $CREATE_FILE 2>&1
	echo "[END]" >> $CREATE_FILE 2>&1

echo "[U-04] 패스워드 파일 보호"
	echo "[U-04] 패스워드 파일 보호" >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
	echo "[START]"  >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
	echo "판단기준 : shadow 파일을 사용하거나, 패스워드를 암호화하여 저장하는 경우" >> $CREATE_FILE 2>&1

	case $OS in
		SunOS)
			echo "**********************" >> $CREATE_FILE 2>&1
			echo "두번째 필드가 x 표시되어 있는지 확인" >> $CREATE_FILE 2>&1
			echo "**********************" >> $CREATE_FILE 2>&1
			echo "1. 현황 : ls -al /etc/passwd /etc/shadow" >> $CREATE_FILE 2>&1
			ls -al /etc/passwd /etc/shadow  >> $CREATE_FILE 2>&1
			echo "2. 현황 : /etc/passwd" >> $CREATE_FILE 2>&1
			cat /etc/passwd >> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1
			echo "3. 현황 : /etc/shadow" >> $CREATE_FILE 2>&1
			cat /etc/shadow >> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1
			;;
		Linux)
			echo "판단기준 참고 : shadow 파일에서 두번째 필드의 x 표기 여부 확인" >> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1
			echo "1. 현황 : ls -al /etc/passwd /etc/shadow" >> $CREATE_FILE 2>&1
			ls -al /etc/passwd /etc/shadow >> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1
			echo "2. 현황 : /etc/passwd 상세 내용" >> $CREATE_FILE 2>&1
			cat /etc/passwd  | grep -v '^#' >> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1
			echo "3. 현황 : /etc/shadow 상세 내용" >> $CREATE_FILE 2>&1
			cat /etc/shadow  | grep -v '^#' >> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1
			;;
		AIX)
			echo "1. 현황 : ls -al /etc/passwd /etc/shadow /etc/security/passwd" >> $CREATE_FILE 2>&1
			ls -al /etc/passwd /etc/shadow /etc/security/passwd >> $CREATE_FILE 2>&1
			echo "2. 현황 : cat /etc/passwd" >> $CREATE_FILE 2>&1
			cat /etc/passwd >> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1
			echo "3. 현황 : /etc/shadow" >> $CREATE_FILE 2>&1
			cat /etc/shadow >> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1
			echo "4. 현황 : /etc/security/passwd" >> $CREATE_FILE 2>&1
			cat /etc/security/passwd >> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1
			;;
		HP-UX)
			echo "1. 현황 : ls -al /etc/passwd /etc/shadow" >> $CREATE_FILE 2>&1
			ls -al /etc/passwd /etc/shadow  >> $CREATE_FILE 2>&1
			echo "2. 현황 : cat /etc/passwd" >> $CREATE_FILE 2>&1
			cat /etc/passwd >> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1
			echo "3. 현황 : cat /etc/shadow" >> $CREATE_FILE 2>&1
			cat /etc/shadow >> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1
			echo "4. 현황 : cat /tcb/files/auth" >> $CREATE_FILE 2>&1
			cat /tcb/files/auth >> $PASS_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1
			;;
	esac
	echo "[END]" >> $CREATE_FILE 2>&1

echo "[U-44] root 이외의 UID가 "0" 금지"
	echo "[U-44] root 이외의 UID가 "0" 금지" >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
	echo "[START]"  >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
	echo "판단기준 : root 계정과 동일한 UID를 갖는 계정이 존재하지 않는 경우" >> $CREATE_FILE 2>&1
		echo " " >> $CREATE_FILE 2>&1
		echo "1. 현황 : 계정별 UID 확인" >> $CREATE_FILE 2>&1
		if [ -f /etc/passwd ]
			then
				awk -F: '$3==0 { print $1 " -> UID=" $3 }' /etc/passwd    >> $CREATE_FILE 2>&1
			else
				echo "/etc/passwd 파일 미존재"	>> $CREATE_FILE 2>&1
		fi
		
		echo " " >> $CREATE_FILE 2>&1
		echo "2. 현황 : /etc/passwd 상세 내용"  >> $CREATE_FILE 2>&1
		cat /etc/passwd >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
	echo "[END]" >> $CREATE_FILE 2>&1

echo "[U-45] root 계정 SU 제한"
	echo "[U-45] root 계정 SU 제한" >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
	echo "[START]"  >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
	echo "판단기준 : SU 명령어를 특정 그룹에 속한 사용자만 사용하도록 제한 되어 있는 경우 (SU 파일 권한이 4750 인 경우)" >> $CREATE_FILE 2>&1

	case $OS in
		SunOS)

			if [ -s /usr/bin/su ]
				then
					echo "1. 현황 : /usr/bin/su 확인 " >> $CREATE_FILE 2>&1
					ls -al /usr/bin/su   									>> $CREATE_FILE 2>&1
					sunsugroup=`ls -al /usr/bin/su | awk '{print $4}'`;		
				else
					echo "1. 현황 : /usr/bin/su 파일을 찾을 수 없습니다."     		>> $CREATE_FILE 2>&1
			fi
			echo " " >> $CREATE_FILE 2>&1
			echo "2. 현황 : su파일의 group 확인 " >> $CREATE_FILE 2>&1
			cat /etc/group | grep -w $sunsugroup >> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1
			echo "3. 현황 : /etc/group" >> $CREATE_FILE 2>&1
			cat /etc/group >> $CREATE_FILE 2>&1
			;;
		Linux)
			echo " " >> $CREATE_FILE 2>&1
			if [ -s /bin/su ]
				then
					echo "1. 현황 :" >> $CREATE_FILE 2>&1
					ls -al /bin/su   									>> $CREATE_FILE 2>&1
					sugroup=`ls -al /bin/su | awk '{print $4}'`;
				else
					echo "/bin/su 파일 미존재"	>> $CREATE_FILE 2>&1
			fi
			echo " " >> $CREATE_FILE 2>&1
			echo "2. 현황 : /etc/group에서 wheel 그룹 확인" >> $CREATE_FILE 2>&1
			grep -E "$sugroup" /etc/group >> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1
			echo "3. 현황 : /etc/group 상세 내용" >> $CREATE_FILE 2>&1
			cat /etc/group >> $CREATE_FILE 2>&1
			;;
		AIX)
			echo "1. 현황 : /etc/security/user의 $ugroup=staff 설정확인" >> $CREATE_FILE 2>&1
			cat /etc/security/user >> $CREATE_FILE 2>&1
			
			if [ -s /usr/bin/su ]
				then
					echo "2. 현황 : /usr/bin/su 확인 " >> $CREATE_FILE 2>&1
					ls -al /usr/bin/su   									>> $CREATE_FILE 2>&1
					sunsugroup=`ls -al /usr/bin/su | awk '{print $4}'`;		
				else
					echo "2. 현황 : /usr/bin/su 파일을 찾을 수 없습니다."     		>> $CREATE_FILE 2>&1
			fi
			echo " " >> $CREATE_FILE 2>&1
			echo "3. 현황 : su파일의 그룹 확인 " >> $CREATE_FILE 2>&1
			cat /etc/group | grep $sunsugroup >> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1
			echo "4. 현황 : /etc/group 파일 확인 " >> $CREATE_FILE 2>&1		
			cat /etc/group >> $CREATE_FILE 2>&1
			;;
		HP-UX)
			echo "1. 현황 : /etc/defualt/security의 SU_ROOT_GROUP=wheel 설정 확인" >> $CREATE_FILE 2>&1
			cat /etc/default/security >> $CREATE_FILE 2>&1

			if [ -s /usr/bin/su ]
				then
					echo "2. 현황 : /usr/bin/su 파일 확인" >> $CREATE_FILE 2>&1
					ls -al /usr/bin/su >> $CREATE_FILE 2>&1
					sunsugroup=`ls -al /usr/bin/su | awk '{print $4}'`;
				else
					echo "2. 현황 /usr/bin/su 파일을 찾을 수 없습니다." >> $CREATE_FILE 2>&1
			fi
			echo " " >> $CREATE_FILE 2>&1
			echo "3. 현황 : su 파일의 그룹 확인 " >> $CREATE_FILE 2>&1
			cat /etc/group | grep $sunsugroup >> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1
			echo "4. 현황 : /etc/group 확인 " >> $CREATE_FILE 2>&1
			cat /etc/group >> $CREATE_FILE 2>&1
			;;
	esac
	echo " " >> $CREATE_FILE 2>&1
	echo "[END]" >> $CREATE_FILE 2>&1

echo "[U-46] 패스워드 최소 길이 설정"
	echo "[U-46] 패스워드 최소 길이 설정" >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
	echo "[START]"  >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
	echo "판단기준 : 패스워드 최소 길이가 8자 이상으로 설정되어 있는 경우 (공공기관의 경우 9자리 이상)" >> $CREATE_FILE 2>&1
	case $OS in
		SunOS)
			echo "1. 현황 : /etc/default/passwd의 최소길이(PASSLENGTH) 확인" >> $CREATE_FILE 2>&1
			cat /etc/default/passwd | grep PASSLENGTH >> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1
			echo "2. 현황 : /etc/default/passwd" >> $CREATE_FILE 2>&1
			cat /etc/default/passwd  >> $CREATE_FILE 2>&1
			;;
		Linux)
			echo "판단기준 참고 : /etc/login.defs 파일의 PASS_MIN_LEN 확인 " >> $CREATE_FILE 2>&1
			echo "1. 현황 : PASS_MIN_LEN 확인 " >> $CREATE_FILE 2>&1
			cat /etc/login.defs | grep -i 'PASS_MIN_LEN' | grep -v '^#'	>> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1
			echo "2. 현황 : /etc/login.defs 상세 내용" >> $CREATE_FILE 2>&1
			cat /etc/login.defs | grep -v '^#' >> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1
			;;
		AIX)
			echo "1. 현황 : /etc/security/user의 minlen 확인" >> $CREATE_FILE 2>&1
			cat /etc/security/user | grep minlen >> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1
			echo "2. 현황 : /etc/security/user 확인" >> $CREATE_FILE 2>&1
			cat /etc/security/user >> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1
			echo "3. 현황 : lsuser -a minlen ALL" >> $CREATE_FILE 2>&1
			lsuser -a minlen ALL >> $CREATE_FILE 2>&1
			;;
		HP-UX)
			echo "1. 현황 : /etc/default/security의 MIN_PASSWORD_LENGTH 확인" >> $CREATE_FILE 2>&1
			cat /etc/default/security | grep MIN_PASSWORD_LENGTH >> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1
			echo "2. 현황 : /etc/default/security 확인" >> $CREATE_FILE 2>&1
			cat /etc/default/security >> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1
			;;
	esac
	echo " " >> $CREATE_FILE 2>&1
	echo "[END]" >> $CREATE_FILE 2>&1

echo "[U-47] 패스워드 최대 사용기간 설정"
	echo "[U-47] 패스워드 최대 사용기간 설정" >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
	echo "[START]"  >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
	echo "판단기준 : 패스워드 최대 길이가 90일(12주) 이하로 설정되어 있는 경우" >> $CREATE_FILE 2>&1
	case $OS in
		SunOS)
			echo "1. 현황 : /etc/default/passwd | grep MAXWEEKS" >> $CREATE_FILE 2>&1		
			cat /etc/default/passwd | grep MAXWEEKS >> $CREATE_FILE 2>&1		
			echo " " >> $CREATE_FILE 2>&1
			echo "2. 현황 : /etc/default/passwd" >> $CREATE_FILE 2>&1		
			cat /etc/default/passwd  >> $CREATE_FILE 2>&1		
			echo " " >> $CREATE_FILE 2>&1
			;;
		Linux)
			echo "판단기준 참고 : /etc/login.defs 파일의 PASS_MAX_DAYS 확인 " >> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1
			echo "1. 현황 : " >> $CREATE_FILE 2>&1
			cat /etc/login.defs | grep -i 'PASS_MAX_DAYS' | grep -v '^#'	>> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1
			echo "2. 현황 : /etc/login.defs 상세 내용" >> $CREATE_FILE 2>&1
			cat /etc/login.defs | grep -v '^#' >> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1
			;;
		AIX)	
			echo "1. 현황 : /etc/security/user | grep maxage" >> $CREATE_FILE 2>&1
			cat /etc/security/user | grep maxage>> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1
			echo "2. 현황 : /etc/security/user" >> $CREATE_FILE 2>&1
			cat /etc/security/user >> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1
			echo "lsuser -a maxage ALL" >> $CREATE_FILE 2>&1
			lsuser -a maxage ALL >> $CREATE_FILE 2>&1
			;;
		HP-UX)
			echo "1. 현황 : /etc/default/security | grep PASSWORD_MAXDAYS" >> $CREATE_FILE 2>&1
			cat /etc/default/security | grep PASSWORD_MAXDAYS >> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1
			echo "2. 현황 : /etc/default/security" >> $CREATE_FILE 2>&1
			cat /etc/default/security >> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1
			;;
	esac
	echo " " >> $CREATE_FILE 2>&1
	echo "[END]" >> $CREATE_FILE 2>&1

echo "[U-48] 패스워드 최소 사용기간 설정"
	echo "[U-48] 패스워드 최소 사용기간 설정" >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
	echo "[START]"  >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
	echo "판단기준 : 패스워드 최소 길이가 설정되어 있는 경우 " >> $CREATE_FILE 2>&1

	case $OS in
		SunOS)
			echo "1. 현황 : /etc/default/passwd | grep MINWEEK" >> $CREATE_FILE 2>&1
			cat /etc/default/passwd | grep MINWEEK >> $CREATE_FILE 2>&1	
			echo " " >> $CREATE_FILE 2>&1
			echo "2. 현황 : /etc/default/passwd" >> $CREATE_FILE 2>&1
			cat /etc/default/passwd  >> $CREATE_FILE 2>&1		
			echo " " >> $CREATE_FILE 2>&1
			;;
		Linux)
			echo "판단기준 참고 : /etc/login.defs 파일의 PASS_MIN_DAYS 확인 " >> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1
			echo "1. 현황 : " >> $CREATE_FILE 2>&1
			cat /etc/login.defs | grep -i 'PASS_MIN_DAYS' | grep -v '^#'	>> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1
			echo "2. 현황 : /etc/login.defs 상세 내용" >> $CREATE_FILE 2>&1
			cat /etc/login.defs | grep -v '^#' >> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1
			;;
		AIX)
			echo "1. 현황 : /etc/security/user | grep minage" >> $CREATE_FILE 2>&1
			cat /etc/security/user >> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1
			echo "2. 현황 : /etc/security/user" >> $CREATE_FILE 2>&1
			cat /etc/security/user >> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1
			echo "3. 현황 : lsuser -a minage ALL" >> $CREATE_FILE 2>&1
			lsuser -a minage ALL >> $CREATE_FILE 2>&1
			echo " "  >> $CREATE_FILE 2>&1
			;;
		HP-UX)
			echo "1. 현황 : /etc/default/security | grep PASSWORD_MINDAYS" >> $CREATE_FILE 2>&1
			cat /etc/default/security | grep PASSWORD_MINDAYS >> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1
			echo "2. 현황 : /etc/default/security" >> $CREATE_FILE 2>&1
			cat /etc/default/security >> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1
			;;
	esac
	echo " " >> $CREATE_FILE 2>&1
	echo "[END]" >> $CREATE_FILE 2>&1

echo "[U-49] 불필요한 계정 제거"
	echo "[U-49] 불필요한 계정 제거" >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
	echo "[START]"  >> $CREATE_FILE 2>&1
	echo "판단기준 : 불필요한 계정이 존재하지 않는 경우 양호" >> $CREATE_FILE 2>&1
	echo "판단기준 : 사용하지 않는 Default 계정(lp, uucp, nuucp) 점검" >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
		if [ `cat /etc/passwd | egrep "lp|uucp|nuucp" | wc -l` -eq 0 ]
		then
			echo "1. 현황 : lp, uucp, nuucp 계정 미존재" >> $CREATE_FILE 2>&1
		else
			echo "1. 현황 : /etc/passwd에서 Default 계정 조회"	>> $CREATE_FILE 2>&1
			cat /etc/passwd | egrep "lp|uucp" >> $CREATE_FILE 2>&1  
			#오류나서 수정 egrep -w 가 유닉스게열에서 안됨
		fi
		echo " " >> $CREATE_FILE 2>&1
		
		echo "2. 최근 로그인 하지 않은 계정 및 의심스러운 계정 확인 " >> $CREATE_FILE 2>&1
	case $OS in
		SunOS | HP-UX)
			echo "2-1. 현황 : 터미널 로그인 시간 확인 (finger)" >> $CREATE_FILE 2>&1
			finger  >> $CREATE_FILE 2>&1  
			echo " " >> $CREATE_FILE 2>&1
			;;
		Linux | AIX)
			echo "2-1. 현황 : 마지막 로그인 시간 확인 (lastlog)" >> $CREATE_FILE 2>&1
			lastlog  >> $CREATE_FILE 2>&1 
			;;
	esac

	echo " " >> $CREATE_FILE 2>&1
	echo "3. 현황 : wtmp(last) 접속로그 확인" >> $CREATE_FILE 2>&1
	last >> $CREATE_FILE 2>&1  
	echo " " >> $CREATE_FILE 2>&1

	echo " " >> $CREATE_FILE 2>&1
	echo "[END]" >> $CREATE_FILE 2>&1

echo "[U-50] 관리자 그룹에 최소한의 계정 포함" 
	echo "[U-50] 관리자 그룹에 최소한의 계정 포함"  >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
	echo "[START]"  >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
	echo "판단기준 : 관리자 그룹(root or system)에 불필요한 계정이 등록되어 있지 않은 경우"  >> $CREATE_FILE 2>&1	
	echo " " >> $CREATE_FILE 2>&1
	case $OS in
		SunOS | HP-UX | Linux)
			echo "1. 현황 : root 그룹 확인" >> $CREATE_FILE 2>&1
			cat /etc/group | grep root  >> $CREATE_FILE 2>&1  
			echo " " >> $CREATE_FILE 2>&1
			;;
		AIX)
			echo "1. 현황 : system 그룹 확인" >> $CREATE_FILE 2>&1
			cat /etc/group | grep system  >> $CREATE_FILE 2>&1 
			echo " "  >> $CREATE_FILE 2>&1
			;;
	esac

	echo "2. 현황 : /etc/passwd (참고)" >> $CREATE_FILE 2>&1
	cat /etc/passwd | grep -v '^#' >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
	echo "[END]" >> $CREATE_FILE 2>&1

echo "[U-51] 계정이 존재하지 않는 GID 금지" 
	echo "[U-51] 계정이 존재하지 않는 GID 금지"  >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
	echo "[START]"  >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
	echo "판단기준 : 불필요한 그룹(계정이 존재하지 않거나 운영에 사용되지 않는 그룹)이 존재하는 경우 취약">> $CREATE_FILE 2>&1
	echo "판단기준 참고 : /etc/group 및 /etc/passwd 파일을 비교해 판단">> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
	echo "1. 현황 : /etc/group 그룹 확인"  >> $CREATE_FILE 2>&1
	cat /etc/group | grep -v '^#' >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
	echo "2. 현황 : /etc/passwd 확인" >> $CREATE_FILE 2>&1
	cat /etc/passwd | grep -v '^#' >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
	echo "[END]" >> $CREATE_FILE 2>&1

echo "[U-52] 동일한 UID 금지" 
		echo "[U-52] 동일한 UID 금지"  >> $CREATE_FILE 2>&1
		echo " " >> $CREATE_FILE 2>&1
		echo "[START]"  >> $CREATE_FILE 2>&1
		echo " " >> $CREATE_FILE 2>&1
		echo "판단기준 : 동일한 UID 사용하는 계정 있는지 확인(없으면 양호)">> $CREATE_FILE 2>&1
		echo " " >> $CREATE_FILE 2>&1	
			echo "1. 현황 : /etc/passwd에서 UID 추출" >> $CREATE_FILE 2>&1
			for uid in `cat /etc/passwd | awk -F: '{print $3}'`
			do
				cat /etc/passwd | awk -F: '$3=="'${uid}'" { print "UID=" $3 " -> " $1 }'        >> $CREATE_FILE 2>&1
			done
		echo " " >> $CREATE_FILE 2>&1
		echo "[END]" >> $CREATE_FILE 2>&1

echo "[U-53] 사용자 shell점검" 
		echo "[U-53] 사용자 shell점검"  >> $CREATE_FILE 2>&1
		echo " " >> $CREATE_FILE 2>&1
		echo "[START]"  >> $CREATE_FILE 2>&1
		echo " " >> $CREATE_FILE 2>&1
		echo "판단기준 : 로그인이 필요하지 않은 계정에 /bin/false(/sbin/nologin)이 부여되어 있으면 양호" >> $CREATE_FILE 2>&1
		echo " " >> $CREATE_FILE 2>&1

			echo "1. 현황 : 로그인이 불필요한 계정의 SHELL 점검 (/etc/passwd) " >> $CREATE_FILE 2>&1
			if [ -f /etc/passwd ]
			then
				cat /etc/passwd | egrep "^daemon|^bin|^sys|^adm|^listen|^nobody|^nobody4|^noaccess|^diag|^operator|^games|^gopher" | grep -v "admin" >> $CREATE_FILE 2>&1
			else
				echo "/etc/passwd 파일 미존재"     >> $CREATE_FILE 2>&1
			fi
		echo " " >> $CREATE_FILE 2>&1
		echo "[END]" >> $CREATE_FILE 2>&1

echo "[U-54] Session Timeout 설정" 
		echo "[U-54] Session Timeout 설정"  >> $CREATE_FILE 2>&1
		echo " " >> $CREATE_FILE 2>&1
		echo "[START]"  >> $CREATE_FILE 2>&1
		echo " " >> $CREATE_FILE 2>&1
		echo "판단기준 : Session TIMEOUT=600(10분) 이하로 설정되어 있으면 양호" >> $CREATE_FILE 2>&1
		case $OS in
			SunOS)
				echo "1. 현황 : /etc/profile의 TMOUT 확인 " >> $CREATE_FILE 2>&1	
				grep -i "TMOUT" /etc/profile | grep -v "^#" >> $CREATE_FILE 2>&1
				echo " " >> $CREATE_FILE 2>&1
				echo "2. 현황 : 환경설정(env) 부분의 TMOUT 확인 " >> $CREATE_FILE 2>&1	
				env | grep TMOUT >> $CREATE_FILE 2>&1
				echo " " >> $CREATE_FILE 2>&1
				;;
			Linux)
				echo "판단기준 참고 : /etc/profile 파일의 TIMEOUT=600 혹은 TMOUT=600 이상이면 양호" >> $CREATE_FILE 2>&1
				echo " " >> $CREATE_FILE 2>&1
				echo "1. 현황 : /etc/profile 파일의 TIMEOUT/TMOUT 확인" >> $CREATE_FILE 2>&1
				grep -i "TIMEOUT" /etc/profile | grep -v "^#" >> $CREATE_FILE 2>&1
				grep -i "TMOUT" /etc/profile | grep -v "^#" >> $CREATE_FILE 2>&1 #문구수정
				echo " " >> $CREATE_FILE 2>&1
				echo "판단기준 참고 : /etc/csh.login 또는 /etc/csh.cshrc의 autologout값이 10 이상이면 양호" >> $CREATE_FILE 2>&1
				echo " " >> $CREATE_FILE 2>&1
				echo "2-1. 현황 : grep -i "autologout" /etc/csh.login | grep -v "^#"" >> $CREATE_FILE 2>&1
				grep -i "autologout" /etc/csh.login | grep -v "^#" >> $CREATE_FILE 2>&1
				echo " " >> $CREATE_FILE 2>&1
				echo "2-2. 현황 : grep -i "autologout" /etc/csh.cshrc | grep -v "^#"" >> $CREATE_FILE 2>&1
				grep -i "autologout" /etc/csh.cshrc | grep -v "^#" >> $CREATE_FILE 2>&1
				echo " " >> $CREATE_FILE 2>&1
				#이거 csh 이 아니라 bash, zsh case 도 있어야함
				;;
			AIX)
				echo "1. 현황 : /etc/profile의 TMOUT 확인 " >> $CREATE_FILE 2>&1	
				grep -i "TIMEOUT" /etc/profile | grep -v "^#" >> $CREATE_FILE 2>&1
				echo " " >> $CREATE_FILE 2>&1
				grep -i "TMOUT" /etc/profile | grep -v "^#" >> $CREATE_FILE 2>&1
				echo " " >> $CREATE_FILE 2>&1
				echo "2. 현황 : csh 인경우(csh.login, csh.cshrc)의 TMOUT 확인 " >> $CREATE_FILE 2>&1	
				echo " " >> $CREATE_FILE 2>&1
				grep -i "autologout" /etc/csh.login | grep -v "^#" >> $CREATE_FILE 2>&1
				echo " " >> $CREATE_FILE 2>&1
				grep -i "autologout" /etc/csh.cshrc | grep -v "^#" >> $CREATE_FILE 2>&1
				echo " " >> $CREATE_FILE 2>&1
				;;
			HP-UX)
				echo "1. 현황 : /etc/profile의 TMOUT 확인 " >> $CREATE_FILE 2>&1
				grep -i "TIMEOUT" /etc/profile | grep -v "^#" >> $CREATE_FILE 2>&1
				echo " " >> $CREATE_FILE 2>&1
				grep -i "TMOUT" /etc/profile | grep -v "^#" >> $CREATE_FILE 2>&1
				echo " " >> $CREATE_FILE 2>&1
				echo "2. 현황 : csh 인경우(csh.login, csh.cshrc)의 TMOUT 확인 " >> $CREATE_FILE 2>&1	
				grep -i "autologout" /etc/csh.login | grep -v "^#" >> $CREATE_FILE 2>&1
				echo " " >> $CREATE_FILE 2>&1
				grep -i "autologout" /etc/csh.cshrc | grep -v "^#" >> $CREATE_FILE 2>&1
				echo " " >> $CREATE_FILE 2>&1
				;;
		esac
		echo " " >> $CREATE_FILE 2>&1
		echo "[END]" >> $CREATE_FILE 2>&1

echo "[U-05] root 홈, 패스 디렉터리 권한 및 패스 설정"
		echo "[U-05] root 홈, 패스 디렉터리 권한 및 패스 설정"  >> $CREATE_FILE 2>&1
		echo " " >> $CREATE_FILE 2>&1
		echo "[START]"  >> $CREATE_FILE 2>&1
		echo "판단기준 : PATH 환경변수에서 "."(DOT)이 맨 뒤에 위치하거나 없으면 양호" >> $CREATE_FILE 2>&1
		echo " " >> $CREATE_FILE 2>&1
		echo "현황 : PATH 환경변수"  >> $CREATE_FILE 2>&1
		echo $PATH  >> $CREATE_FILE 2>&1
		echo " " >> $CREATE_FILE 2>&1
		echo "[END]" >> $CREATE_FILE 2>&1


echo "[U-06] 파일 및 디렉터리 소유자 설정"  
		echo "[U-06] 파일 및 디렉터리 소유자 설정"  >> $CREATE_FILE 2>&1
		echo " " >> $CREATE_FILE 2>&1
		echo "[START]"  >> $CREATE_FILE 2>&1
		echo " " >> $CREATE_FILE 2>&1
		echo "판단기준 : 소유자가 존재하지 않는 파일 디렉토리 중 중요한 파일인지 확인" >> $CREATE_FILE 2>&1
		case $OS in
			SunOS)
				echo "현황 : find / -nouser -o -nogroup -xdev -ls 2> /dev/null" >> $CREATE_FILE 2>&1
				find / -nouser -o -nogroup -xdev -ls 2>/dev/null  >> $CREATE_FILE 2>&1
				echo " " >> $CREATE_FILE 2>&1
				;;
			Linux)
				echo "1. 현황 : find / ( -nouser -o -nogroup ) -xdev " >> $CREATE_FILE 2>&1
				find / \( -nouser -o -nogroup \) -xdev -exec ls -al {} \; 2>/dev/null  >> $CREATE_FILE 2>&1
				echo " " >> $CREATE_FILE 2>&1
				#echo "2. 현황 : find / -nogroup -ls " >> $CREATE_FILE 2>&1
				#find / -xdev -nogroup -ls 2>/dev/null  >> $CREATE_FILE 2>&1
				#echo " " >> $CREATE_FILE 2>&1
				;;
			AIX)
				echo "현황 : find / -nouser -o -nogroup -xdev -ls 2> /dev/null" >> $CREATE_FILE 2>&1
				find / -nouser -o -nogroup -xdev -ls 2>/dev/null  >> $CREATE_FILE 2>&1
				echo " " >> $CREATE_FILE 2>&1		
				;;
			HP-UX)
				echo "현황 : find / \( -nouser -o -nogroup \) -xdev -exec ls -al {} \; 2> /dev/null" >> $CREATE_FILE 2>&1
				find / \( -nouser -o -nogroup \) -xdev -exec ls -al {} \; 2>/dev/null  >> $CREATE_FILE 2>&1
				echo " " >> $CREATE_FILE 2>&1		
				;;
		esac
		echo " " >> $CREATE_FILE 2>&1
		echo "[END]" >> $CREATE_FILE 2>&1

echo "[U-07] /etc/passwd 파일 소유자 및 권한 설정"  
	echo "[U-07] /etc/passwd 파일 소유자 및 권한설정"  >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
	echo "[START]"  >> $CREATE_FILE 2>&1
	echo "판단기준 : /etc/passwd 파일의 소유자가 root이고, 파일권한이 644이하이면 양호" >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
	echo "현황 : ls -al /etc/passwd" >> $CREATE_FILE 2>&1
	ls -al /etc/passwd >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
	echo "[END]" >> $CREATE_FILE 2>&1


echo "[U-08] /etc/shadow 파일 소유자 및 권한설정"  
	echo "[U-08] /etc/shadow 파일 소유자 및 권한설정"  >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
	echo "[START]"  >> $CREATE_FILE 2>&1
	echo "판단기준 : /etc/shadow 파일의 소유자가 root이고, 파일권한이 400 이하이면 양호" >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1

	case $OS in
		SunOS | Linux)
			echo "현황 : ls -al /etc/shadow" >> $CREATE_FILE 2>&1
			ls -al /etc/shadow >> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1
			;;
		AIX)
			echo "현황 : ls -al /etc/shadow" >> $CREATE_FILE 2>&1
			ls -al /etc/shadow  >> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1
			echo "현황 : ls -al /etc/security/passwd" >> $CREATE_FILE 2>&1
			ls -al /etc/security/passwd  >> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1		
			;;
		HP-UX)
			echo "현황 : ls -al /etc/shadow" >> $CREATE_FILE 2>&1
			ls -al /etc/shadow  >> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1
			echo "현황 : ls -alL /tcb/files/auth" >> $CREATE_FILE 2>&1
			ls -alL /tcb/files/auth  >> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1
			;;
	esac
	echo " " >> $CREATE_FILE 2>&1
	echo "[END]" >> $CREATE_FILE 2>&1


echo "[U-09] /etc/hosts 파일 소유자 및 권한 설정"  
	echo "[U-09] /etc/hosts 파일 소유자 및 권한 설정"  >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
	echo "[START]"  >> $CREATE_FILE 2>&1
	echo "판단기준 : /etc/hosts 파일의 소유자가 root이고, 파일권한이 600이하이면 양호" >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
	echo "현황 : ls -alL /etc/hosts"  >> $CREATE_FILE 2>&1
	ls -alL /etc/hosts >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
	echo "[END]" >> $CREATE_FILE 2>&1


echo "[U-10] /etc/(x)inetd.conf 파일 소유자 및 권한 설정"  
	echo "[U-10] /etc/(x)inetd.conf 파일 소유자 및 권한 설정"  >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
	echo "[START]"  >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
	echo "판단기준 : /etc/(x)inetd.conf 파일의 소유자가 root이고, 권한이 600 이하이면 양호" >> $CREATE_FILE 2>&1
	case $OS in
		SunOS | AIX | HP-UX)
			echo "1. 현황 : ls -al /etc/inetd.conf" >> $CREATE_FILE 2>&1
			ls -al /etc/inetd.conf  >> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1
			echo "2. 현황 : ls -al /etc/inet/inetd.conf" >> $CREATE_FILE 2>&1
			ls -al /etc/inet/inetd.conf  >> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1
			;;
		Linux)
			echo "1. 현황 : ls -l /etc/xinetd.conf" >> $CREATE_FILE 2>&1
			ls -l /etc/xinetd.conf  >> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1
			echo "2. 현황 : ls -al /etc/xinetd.d/* (참고) " >> $CREATE_FILE 2>&1
			ls -al /etc/xinetd.d/*  >> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1
			;;
	esac
	echo " " >> $CREATE_FILE 2>&1
	echo "[END]" >> $CREATE_FILE 2>&1


echo "[U-11] /etc/syslog.conf 파일 소유자 및 권한 설정"  
	echo "[U-11] /etc/syslog.conf 파일 소유자 및 권한 설정"  >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
	echo "[START]"  >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
	echo "판단기준 : /etc/syslog.conf 파일의 소유자가 root(또는 bin,sys)이고, 권한이 644 이하이면 양호" >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
		echo "1. 현황 : syslog 서비스 확인" >> $CREATE_FILE 2>&1
		ps -ef | grep 'syslog' | grep -v 'grep' >> $CREATE_FILE 2>&1
		echo " " >> $CREATE_FILE 2>&1 
		echo "2. 현황 : syslog.conf 파일 확인" >> $CREATE_FILE 2>&1
		ls -al /etc/syslog.conf >> $CREATE_FILE 2>&1	
		ls -al /etc/isyslog.conf >> $CREATE_FILE 2>&1	
		ls -al /etc/rsyslog.conf >> $CREATE_FILE 2>&1
		ls -al /etc/syslog-ng/syslog-ng.conf >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
	echo "[END]" >> $CREATE_FILE 2>&1


echo "[U-12] /etc/services 파일 소유자 및 권한설정"  
	echo "[U-12] /etc/services 파일 소유자 및 권한설정"  >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
	echo "[START]"  >> $CREATE_FILE 2>&1
	echo "판단기준 참고 : /etc/services 파일의 소유자가 root이고, 퍼미션이 644 이하이면 양호" >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
		echo "현황 : ls -alL /etc/services" >> $CREATE_FILE 2>&1
		ls -alL /etc/services >> $CREATE_FILE 2>&1
		ls -al /etc/inet/services >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
	echo "[END]" >> $CREATE_FILE 2>&1


echo "[U-13] SUID, SGID, Sticky bit 설정 파일 점검"  
	echo "[U-13] SUID, SGID, Sticky bit 설정 파일 점검"  >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
	echo "[START]"  >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
	case $OS in
		SunOS)
			echo "판단기준 참고 : 중요 파일 및 디렉터리의 SUID, SGID, Sticky bit 설정이 4750인지 확인" >> $CREATE_FILE 2>&1
			ls -al /usr/bin/admintool /usr/bin/at /usr/bin/atq /usr/bin/atrm /usr/bin/lpset /usr/bin/newgrp /usr/bin/nispasswd /usr/bin/rdist /usr/bin/yppasswd /usr/dt/bin/dtappgather /usr/dt/bin/dtprintinfo /usr/dt/bin/sdtcm_convert /usr/lib/fs/ufs/ufsdump /usr/lib/fs/ufs/ufsrestore /usr/lib/lp/bin/netpr /usr/openwin/bin/ff.core /usr/openwin/bin/kcms_calibrate /usr/openwin/bin/kcms_configure /usr/openwin/bin/xlock /usr/platform/sun4u/sbin/prtdiag /usr/sbin/arp /usr/sbin/lpmove /usr/sbin/prtconf >> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1
			;;
		Linux) ##################################################
			echo "판단기준 참고 : 중요 파일 및 디렉터리의 SUID, SGID, Sticky bit 설정이 4750인지 확인" >> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1
			ls -al /sbin/dump /usr/bin/lpq-lpd /usr/bin/newgrp /sbin/restore /usr/bin/lpr /usr/sbin/lpc /sbin/unix_chkpwd /usr/bin/lpr-lpd /usr/sbin/lpc-lpd /usr/bin/at /usr/bin/lprm /usr/sbin/traceroute /usr/bin/lpq /usr/bin/lprm-lpd  >> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1		
			;;
		AIX)
			echo "판단기준 참고 : 중요 파일 및 디렉터리의 SUID, SGID, Sticky bit 설정이 4750인지 확인" >> $CREATE_FILE 2>&1
			ls -al /usr/dt/bin/dtaction /usr/dt/bin/dtterm /usr/bin/X11/xlock /usr/sbin/mount /usr/sbin/lchangelv >> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1
			;;
		HP-UX)
			echo "판단기준 참고 : 중요 파일 및 디렉터리의 SUID, SGID, Sticky bit 설정이 4750인지 확인" >> $CREATE_FILE 2>&1
			ls -al /opt/perf/bin/glance /usr/dt/bin/dtprintinfo /usr/sbin/swreg /opt/perf/bin/gpm /usr/sbin/arp /usr/sbin/swremove /opt/video/lbin/camServer /usr/sbin/lanadmin /usr/bin/at /usr/sbin/landiag /usr/bin/lpalt /usr/sbin/lpsched /usr/bin/mediainit /usr/sbin/swacl /usr/bin/newgrp /usr/sbin/swconfig /usr/bin/rdist /usr/sbin/swinstall /usr/contrib/bin/traceroute /usr/sbin/swmodify /usr/dt/bin/dtappgather /usr/sbin/swpackage >> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1
			;;
	esac
	echo " " >> $CREATE_FILE 2>&1
	echo "[END]" >> $CREATE_FILE 2>&1


echo "[U-14] 사용자, 시스템 시작파일 및 환경파일 소유자 및 권한 설정"  
	echo "[U-14] 사용자, 시스템 시작파일 및 환경파일 소유자 및 권한 설정"  >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
	echo "[START]"  >> $CREATE_FILE 2>&1
		echo "판단기준 참고 : 시스템 환경파일이 있는경우, 소유자가 root이고 권한이 644이하일 경우 양호" >> $CREATE_FILE 2>&1
		echo "판단기준 참고 : 홈 디렉터리 환경변수 파일에 root와 소유자만 쓰기 권한이 부여된 경우 양호" >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
	echo "1. 현황 : 환경변수 파일 확인" >> $CREATE_FILE 2>&1
	case $OS in
		SunOS)
			ls -al /.profile /.cshrc /.kshrc /.login /.bash_profile /.bashrc /.bash_login /.xinitrc /.xsession /.login /.exrc /.netrc  >> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1
			;;
		Linux)
			ls -al /.profile /.cshrc /.kshrc /.login /.bash_profile /.bashrc /.bash_login /.xinitrc /.xsession /.exrc /.netrc  >> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1		
			;;
		AIX)
			ls -al /.profile /.cshrc /.kshrc /.login /.bash_profile /.bashrc /.bash_login /.xinitrc /.xsession /.login /.exrc /.netrc >> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1
			;;
		HP-UX)
			ls -al /.profile /.cshrc /.kshrc /.login /.bash_profile /.bashrc /.bash_login /.xinitrc /.xsession /.exrc /.netrc >> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1
			;;
	esac
	echo "2. 현황 : 홈 디렉토리($HOME) 경로의 쓰기권한 확인 ( 환경변수만 확인하면 됨)" >> $CREATE_FILE 2>&1
	ls -al $HOME/ >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
	echo "[END]" >> $CREATE_FILE 2>&1


echo "[U-15] World writable 파일 점검"  
	echo "[U-15] World writable 파일 점검"  >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
	echo "[START]"  >> $CREATE_FILE 2>&1
	echo "참고판단 기준 >> world writable 파일이 존재하지 않거나, 중요 파일인 경우 644 이하이면 양호 " >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
	case $OS in
		SunOS)
			echo "find / -type f -perm -o=w -ls" >> $CREATE_FILE 2>&1
			find / -type f -perm -o=w -ls 2>/dev/null >> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1
			;;
		Linux)
			echo "현황 : find / ! \( -path /tmp -prune \) -type f -perm -o=w -ls" >> $CREATE_FILE 2>&1
			find / ! \( -path /tmp -prune -o -path /proc -prune \) -type f -perm -o=w -ls 2>/dev/null >> $CREATE_FILE 2>&1 
			echo " " >> $CREATE_FILE 2>&1
			;;
		AIX)
			echo "find / ! \( -path /tmp -prune \) -type f -perm -o=w -ls" >> $CREATE_FILE 2>&1
			find / ! \( -path /tmp -prune \) -type f -perm -o=w -ls 2>/dev/null >> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1
			;;
		HP-UX)
			echo "find / ! \( -path /tmp -prune \) -type f -perm -o=w -exec ls -al {} \;" >> $CREATE_FILE 2>&1
			find / ! \( -path /tmp -prune \) -type f -perm -o=w -exec ls -al {} \; >> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1
			;;
	esac
	echo " " >> $CREATE_FILE 2>&1
	echo "[END]" >> $CREATE_FILE 2>&1


echo "[U-16] /dev에 존재하지 않는 device 파일 점검"  
	echo "[U-16] /dev에 존재하지 않는 device 파일 점검"  >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
	echo "[START]"  >> $CREATE_FILE 2>&1
	echo "판단기준 참고 : 아래 find 결과 값에서 major, minor number 값을 가지고 있는 경우 양호" >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
		echo "현황 : find /dev -type f -exec ls -l {} \;" >> $CREATE_FILE 2>&1
		find /dev -type f -exec ls -l {} \; >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
	echo "[END]" >> $CREATE_FILE 2>&1


echo "[U-17] $HOME/.rhosts, hosts.equiv 사용 금지"  
	echo "[U-17] $HOME/.rhosts, hosts.equiv 사용 금지"  >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
	echo "[START]"  >> $CREATE_FILE 2>&1
	echo "판단기준 : 파일이 존재하지 않거나, 파일 소유자가 root 또는 해당 계정이면서 권한이 600 이하이고 파일에 "+"가 없으면 양호" >> $CREATE_FILE 2>&1
	echo "판단기준 참고 : /etc/hosts.equiv : 서버 설정 파일" >> $CREATE_FILE 2>&1
	echo "판단기준 참고 : $home/.rhosts 개별 사용자의 설정 파일" >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
		echo "1. 현황 : ls -al /etc/hosts.equiv" >> $CREATE_FILE 2>&1
		ls -al /etc/hosts.equiv >> $CREATE_FILE 2>&1
		echo " " >> $CREATE_FILE 2>&1
		cat /etc/hosts.equiv >> $CREATE_FILE 2>&1
		echo " " >> $CREATE_FILE 2>&1
		echo "2. 현황 : ls -al $HOME/.rhosts" >> $CREATE_FILE 2>&1
		ls -al $HOME/.rhosts >> $CREATE_FILE 2>&1
		echo " " >> $CREATE_FILE 2>&1
		cat $HOME/.rhosts >> $CREATE_FILE 2>&1
		echo " " >> $CREATE_FILE 2>&1
	echo "[END]" >> $CREATE_FILE 2>&1


echo "[U-18] 접속 IP 및 포트 제한"
	echo "[U-18] 접속 IP 및 포트 제한"  >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
	echo "[START]"  >> $CREATE_FILE 2>&1
	echo "판단기준 참고 : /etc/hosts.deny 파일 내에 ALL:ALL 설정되어 있고, /etc/hosts.allow 파일 내에 서버로 접속하는 접속 IP대역을 설정했을 경우 양호" >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
		echo "1. 현황 : 차단설정 /etc/hosts.deny" >> $CREATE_FILE 2>&1
		ls -al /etc/hosts.deny | grep -v '^#' >> $CREATE_FILE 2>&1
		echo " " >> $CREATE_FILE 2>&1
		cat /etc/hosts.deny | grep -v '^#' >> $CREATE_FILE 2>&1
		echo " " >> $CREATE_FILE 2>&1
		echo "2. 현황 : 허용설정 /etc/hosts.allow " >> $CREATE_FILE 2>&1
		ls -al /etc/hosts.allow | grep -v '^#' >> $CREATE_FILE 2>&1
		echo " " >> $CREATE_FILE 2>&1
		cat /etc/hosts.allow | grep -v '^#' >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
	echo "[END]" >> $CREATE_FILE 2>&1


echo "[U-55] Hosts.lpd 파일 소유자 및 권한 설정"  
	echo "[U-55] Hosts.lpd 파일 소유자 및 권한 설정"  >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
	echo "[START]"  >> $CREATE_FILE 2>&1
	echo "판단기준 참고 :  파일이 존재하지 않거나, 파일 존재시 소유자가 root이고 권한이 600 이하면 양호" >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
		echo "현황 : ls -alL /etc/hosts.lpd" >> $CREATE_FILE 2>&1
		ls -alL /etc/hosts.lpd >> $CREATE_FILE 2>&1
		echo " " >> $CREATE_FILE 2>&1	
	echo " " >> $CREATE_FILE 2>&1
	echo "[END]" >> $CREATE_FILE 2>&1


	#echo "================================2021년 항목 삭제==========================================" >> $CREATE_FILE 2>&1
	#echo " " >> $CREATE_FILE 2>&1
	#echo "[U-31] NIS 서비스 비활성화"  
	#echo "[U-31] NIS 서비스 비활성화"  >> $CREATE_FILE 2>&1
	#echo "[START]"  >> $CREATE_FILE 2>&1
	#echo "판단기준 참고 : 아래 결과값에 yp 서비스가 노출되지 않으면 비활성화 된 것으로 양호"  >> $CREATE_FILE 2>&1
	#echo " " >> $CREATE_FILE 2>&1
	#	echo "현황 : 서비스 ypserv|ypbind|ypxfrd|rpc.yppasswdd|rpc.ypupdated 확인 (결과값 없을시 양호)" >> $CREATE_FILE 2>&1
	#	SERVICE="ypserv|ypbind|ypxfrd|rpc.yppasswdd|rpc.ypupdated"
	#	ps -ef | egrep $SERVICE | grep -v "grep" >> $CREATE_FILE 2>&1
	#	echo " " >> $CREATE_FILE 2>&1
	#case $OS in
	#	SunOS)
	#		echo "svcs -a | grep nis" >> $CREATE_FILE 2>&1
	#		svcs -a | grep nis >> $CREATE_FILE 2>&1
	#esac
	#echo " " >> $CREATE_FILE 2>&1
	#echo "[END]" >> $CREATE_FILE 2>&1
	#echo " " >> $CREATE_FILE 2>&1
	# 
	#END

echo "[U-56] UMASK 설정 관리"
	echo "[U-56] UMASK 설정 관리"  >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
	echo "[START]"  >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
	echo "판단기준 : /etc/default/login 파일 내에 umask 설정값이 022로 설정되어 있으면 양호 " >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
		echo "1. 현황 : etc/profile umask 설정 " >> $CREATE_FILE 2>&1
		cat /etc/profile | grep  >> $CREATE_FILE 2>&1
		echo " " >> $CREATE_FILE 2>&1
		echo "2. 현황 : umask(명령어) 실행값 = " >> $CREATE_FILE 2>&1
		echo "umask="`umask` >> $CREATE_FILE 2>&1
		echo " " >> $CREATE_FILE 2>&1
	# 리눅스는 삭제함_위에껄로 충분함_2021_01_08 
	# 2.현황에 한번에 출력되지 않도록 변경함 2022-02-15
	case $OS in
		SunOS)
			echo "3. 현황 : /etc/default/login umask 설정 " >> $CREATE_FILE 2>&1
			cat /etc/default/login >> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1
			;;
		AIX)
			echo "3. 현황 : /etc/security/user umask 설정 " >> $CREATE_FILE 2>&1
			cat /etc/security/user >> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1
			echo "4. 현황 :lsuser -a umask ALL" >> $CREATE_FILE 2>&1
			echo "lsuser -a umask ALL " >> $CREATE_FILE 2>&1
			lsuser -a umask ALL >> $CREATE_FILE 2>&1
			;;
		HP-UX)
			echo "3. 현황 : /etc/default/security umask 설정 " >> $CREATE_FILE 2>&1
			cat /etc/default/security >> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1
			;;
	esac
	echo " " >> $CREATE_FILE 2>&1
	echo "[END]" >> $CREATE_FILE 2>&1


echo "[U-57] 홈 디렉터리 소유자 및 권한 설정"  
	echo "[U-57] 홈 디렉터리 소유자 및 권한 설정"  >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
	echo "[START]"  >> $CREATE_FILE 2>&1
	echo "판단기준 : 홈디렉토리 소유자가 해당 계정이고, 타 사용자 쓰기 권한이 제거된 경우" >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
		echo "1. 현황 : 소유자@홈디렉토리" >> $CREATE_FILE 2>&1
		cat /etc/passwd | awk -F":" '{print $1 " @ " $6}' | grep -v "\/\>" | sort -u >> $CREATE_FILE 2>&1
		echo " " >> $CREATE_FILE 2>&1
		echo "2. 현황 : 홈디렉토리의 권한 확인" >> $CREATE_FILE 2>&1
		HOMEDIRS=`cat /etc/passwd | awk -F":" 'length($6) > 0 {print $6}' | grep -wv "\/" | sort -u`     
		for dir in $HOMEDIRS
			do
				ls -dal $dir | grep '\d.........' >> $CREATE_FILE 2>&1
		done
	echo " " >> $CREATE_FILE 2>&1
	echo "[END]" >> $CREATE_FILE 2>&1


echo "[U-58] 홈 디렉터리로 지정한 디렉터리의 존재 관리"  
	echo "[U-58] 홈 디렉터리로 지정한 디렉터리의 존재 관리"  >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
	echo "[START]"  >> $CREATE_FILE 2>&1
	echo "판단기준 : 홈 디렉터리가 없는 사용자가 없는 경우 양호" >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
	echo "현황 : /etc/passwd의 홈디렉토리" >> $CREATE_FILE 2>&1
		for U34 in `cat /etc/passwd | awk -F: 'length($6) > 0 { print $1 }'`
		do
			if [ -d `cat /etc/passwd | grep -w $U34 | awk -F: '{ print $6":"$1 }' | grep $U34$ | awk -F: '{ print $1 }'` ]
			#if [ -d `cat /etc/passwd | grep $U34 | awk -F: '{ print $6":"$1 }' | grep $U34$ | awk -F: '{ print $1 }'` ]
				then
					echo "========" >> $CREATE_FILE 2>&1
					echo "ID : $U34" >> $CREATE_FILE 2>&1
					TMP_HOMEDIR=`cat /etc/passwd | grep -w $U34 | awk -F: '{ print $6":"$1 }' | grep $U34$ | awk -F: '{ print $1 }'`
					#TMP_HOMEDIR=`cat /etc/passwd | grep $U34 | awk -F: '{ print $6":"$1 }' | grep $U34$ | awk -F: '{ print $1 }'`
					echo "해당 디렉토리 있음 : $TMP_HOMEDIR" >> $CREATE_FILE 2>&1
					echo "$TMP_HOMEDIR 존재함" >> $CREATE_FILE 2>&1
				else
					echo "========" >> $CREATE_FILE 2>&1
					echo "ID : $U34" >> $CREATE_FILE 2>&1
					echo " " >> $CREATE_FILE 2>&1
					TMP_HOMEDIR=`cat /etc/passwd | grep -w $U34 | awk -F: '{ print $6":"$1 }' | grep $U34$ | awk -F: '{ print $1 }'`
					#TMP_HOMEDIR=`cat /etc/passwd | grep $U34 | awk -F: '{ print $6":"$1 }' | grep $U34$ | awk -F: '{ print $1 }'`
					echo "디렉토리 없음(취약) : $TMP_HOMEDIR" >> $CREATE_FILE 2>&1
					echo " " >> $CREATE_FILE 2>&1
					echo "$TMP_HOMEDIR 없음" >> $CREATE_FILE 2>&1
			fi
		done
	echo " " >> $CREATE_FILE 2>&1
	echo "[END]" >> $CREATE_FILE 2>&1


echo "[U-59] 숨겨진 파일 및 디렉터리 검색 및 제거"  
	echo "[U-59] 숨겨진 파일 및 디렉터리 검색 및 제거"  >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
	echo "[START]"  >> $CREATE_FILE 2>&1
	echo "판단기준 : 숨겨져 있는 파일 및 디렉터리가 있더라도 시스템상에 영향을 끼치지 않으면 양호" >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
	echo "1. 현황(숨겨진 파일) : find / -name ".*" -type f ">> $CREATE_FILE 2>&1
	
	find / -name ".*" -type f 2>&1 >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
	echo "2. 현황(숨겨진 디렉토리) : find / -name ".*" -type d " >> $CREATE_FILE 2>&1
	find / -name ".*" -type d 2>&1 >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
	echo "[END]" >> $CREATE_FILE 2>&1


echo "[U-19] Finger 서비스 비활성화"
	echo "[U-19] Finger 서비스 비활성화"  >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
	echo "[START]"  >> $CREATE_FILE 2>&1
	echo "판단기준 참고 : 아래 결과 값 내에 파일이 존재하지 않을경우 양호 " >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
	echo "1. 현황 : /etc/inetd.conf">> $CREATE_FILE 2>&1
	cat /etc/inetd.conf >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
	case $OS in
	SunOS)
		echo "2. 현황(SOL 10이상) : inetadm | grep finger">> $CREATE_FILE 2>&1
		inetadm | grep "finger" >> $CREATE_FILE 2>&1
		echo " " >> $CREATE_FILE 2>&1
		;;
	Linux)
		echo "2. 현황(xinetd 일경우) : /etc/xinetd.d" >> $CREATE_FILE 2>&1
		ls -al /etc/xinetd.d >> $CREATE_FILE 2>&1
		echo " " >> $CREATE_FILE 2>&1
		echo "3. 현황(xinetd 일경우) : /etc/xinetd.d/* egrep 'echo finger' " >> $CREATE_FILE 2>&1
		cat /etc/xinetd.d/* | egrep "echo finger" >> $CREATE_FILE 2>&1
		;;
	esac
	echo " " >> $CREATE_FILE 2>&1
	echo "[END]" >> $CREATE_FILE 2>&1


echo "[U-20] Anonymous FTP 비활성화" 
	echo "[U-20] Anonymous FTP 비활성화" >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
	echo "[START]"  >> $CREATE_FILE 2>&1
	echo "판단기준 : Anonymous(익명)에 대한 ftp 접근이 제한되어 있으면 양호 " >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
		echo "1. 현황 : ftp 서비스 확인 " >> $CREATE_FILE 2>&1
		ps -ef | grep ftp | grep -v grep >> $CREATE_FILE 2>&1
		echo " " >> $CREATE_FILE 2>&1

	case $OS in
	SunOS)
		echo "1-2. 현황(SOL 10이상) : svcs ftp">> $CREATE_FILE 2>&1
		svcs ftp >> $CREATE_FILE 2>&1
		echo " " >> $CREATE_FILE 2>&1
		;;
	esac 

	echo "2. 현황 : cat /etc/passwd | egrep 'ftp|anonymous' FTP 계정 삭제 권고" >> $CREATE_FILE 2>&1
	cat /etc/passwd | egrep "ftp|anonymous" >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
	echo "3. 현황 : vsftpd 서비스 확인" >> $CREATE_FILE 2>&1
	ps -ef | grep vsftpd | grep -v grep >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
	echo "4. 현황 : /etc/vsftpd.conf (anonymous_enable=NO 또는 주석처리시 확인)" >> $CREATE_FILE 2>&1
	cat /etc/vsftpd.conf >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
	echo "5. 현황 : /etc/vsftpd/vsftpd.conf" >> $CREATE_FILE 2>&1
	cat /etc/vsftpd/vsftpd.conf >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
	echo "[END]" >> $CREATE_FILE 2>&1


echo "[U-21] r 계열 서비스 비활성화"  
	echo "[U-21] r 계열 서비스 비활성화"  >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
	echo "[START]"  >> $CREATE_FILE 2>&1
	echo "판단기준 참고 : rsh, rlogin, rexec (shell, login, exec) 서비스가 비활성화 되어있거나 결과값이 없을경우에 양호" >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
	case $OS in
		SunOS)
			echo "1-1. 현황(Solaris 9버전 이하) : /etc/inetd.conf 확인하여 r로 시작하는 서비스(rexecd,rlogind,rshd 등) 주석 확인" >> $CREATE_FILE 2>&1
			cat /etc/inetd.conf >> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1
			echo "1-2. 현황(Solaris 10버전 이상) : r서비스 계열 활성화 확인(disable이면 양호)" >> $CREATE_FILE 2>&1
			inetadm | egrep "shell|rlogin|rexec">> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1
			;;
		Linux)
			echo "1. 현황 : 서비스 확인" >> $CREATE_FILE 2>&1
			ls -al /etc/xinetd.d/* | egrep "rsh|rlogin|rexec" | egrep -v "grep|klogin|kshell|kexec" >> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1
			echo "2. rsh, rlogin, rexec 서비스 설정 확인 (Disable=yes 설정시 양호)" >> $CREATE_FILE 2>&1
			echo "2-1. cat /etc/xinetd.d/rsh " >> $CREATE_FILE 2>&1
			cat /etc/xinetd.d/rsh >> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1
			echo "2-2. cat /etc/xinetd.d/rlogin" >> $CREATE_FILE 2>&1
			cat /etc/xinetd.d/rlogin >> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1
			echo "2-3. cat /etc/xinetd.d/rexec" >> $CREATE_FILE 2>&1
			cat /etc/xinetd.d/rexec >> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1
			;;
		AIX)
			cat /etc/inetd.conf >> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1
			;;
		HP-UX)
			cat /etc/inetd.conf  >> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1
			;;
	esac
	echo " " >> $CREATE_FILE 2>&1
	echo "[END]" >> $CREATE_FILE 2>&1


echo "[U-22] cron파일 소유자 및 권한 설정" 
	echo "[U-22] cron파일 소유자 및 권한 설정"  >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
	echo "[START]"  >> $CREATE_FILE 2>&1
	echo "판단기준 : cron 파일의 소유자가 root이고 640이하이면 양호" >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
	case $OS in
		SunOS)
			echo "1. 현황 : /etc/cron.d/cron.allow, deny 파일 권한 확인" >> $CREATE_FILE 2>&1
			ls -al /etc/cron.d/cron* >> $CREATE_FILE 2>&1
			;;
		Linux)
			echo "1. 현황 : /etc/cron.allow, deny 파일 권한 확인" >> $CREATE_FILE 2>&1
			ls -al /etc/cron* >> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1
			;;
		AIX | HP-UX)
			echo "1. 현황 : /var/adm/cron/cron.allow, deny 파일 권한 확인" >> $CREATE_FILE 2>&1
			ls -al /var/adm/cron/cron.* >> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1
			;;
	esac		
		echo " " >> $CREATE_FILE 2>&1
		echo "2. 참고 : /etc -name cron.* -type f -ls 파일 권한 확인" >> $CREATE_FILE 2>&1
		find /etc -name cron.* -type f -ls >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
	echo "[END]" >> $CREATE_FILE 2>&1


echo "[U-23] DoS공격에 취약한 서비스 비활성화"  
	echo "[U-23] DoS공격에 취약한 서비스 비활성화"  >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
	echo "[START]"  >> $CREATE_FILE 2>&1
	echo "판단기준 : echo, discard, daytime, chargen 서비스가 비활성화 되어있거나 결과값이 없을경우에 양호" >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
	case $OS in
		SunOS)
			echo "1-1. 현황(Solaris 9버전 이하) : ps -ef | egrep 'echo|discard|daytime|chargen' 없으면 양호" >> $CREATE_FILE 2>&1
			ps -ef | egrep "echo|discard|daytime|chargen" >> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1
			echo "1-2. 현황(Solaris 9버전 이하) : /etc/inetd.conf | egrep 'echo|discard|daytime|chargen' 확인하여 해당 서비스 주석 확인" >> $CREATE_FILE 2>&1
			cat /etc/inetd.conf | egrep "echo|discard|daytime|chargen" >> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1
			
			echo "1-3. 현황(Solaris 10버전 이상) : 서비스 비활성화(disable) 확인, 결과 없으면 양호" >> $CREATE_FILE 2>&1
			svcs -a | egrep "echo|discard|daytime|chargen" >> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1
			;;
		Linux)
			echo "1. 현황 : ls -al /etc/xinetd.d" >> $CREATE_FILE 2>&1
			ls -al /etc/xinetd.d >> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1 #간격조절
			echo "2. 설정파일 확인 (Disable=yes 설정시 양호)" >> $CREATE_FILE 2>&1
			echo "2-1. 현황 : chargen 확인 " >> $CREATE_FILE 2>&1
			cat /etc/xinetd.d/chargen >> $CREATE_FILE 2>&1
			cat /etc/xinetd.d/chargen-dgram >> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1
			echo "2-2. 현황 : daytime 확인 " >> $CREATE_FILE 2>&1
			cat /etc/xinetd.d/daytime >> $CREATE_FILE 2>&1
			cat /etc/xinetd.d/daytime-dgram >> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1
			echo "2-3. 현황 : discard 확인 " >> $CREATE_FILE 2>&1
			cat /etc/xinetd.d/discard >> $CREATE_FILE 2>&1
			cat /etc/xinetd.d/discard-dgram >> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1
			echo "2-4. 현황 : echo 확인 " >> $CREATE_FILE 2>&1
			cat /etc/xinetd.d/echo >> $CREATE_FILE 2>&1
			cat /etc/xinetd.d/echo-dgram >> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1
			;;
		AIX | HP-UX)
			echo "1. 현황 : /etc/inetd.conf 확인하여 해당 서비스 주석 확인" >> $CREATE_FILE 2>&1
			cat /etc/inetd.conf >> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1
			;;
	esac
	echo " " >> $CREATE_FILE 2>&1
	echo "[END]" >> $CREATE_FILE 2>&1


echo "[U-24] NFS 서비스 비활성화"  
	echo "[U-24] NFS 서비스 비활성화"  >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
	echo "[START]"  >> $CREATE_FILE 2>&1
	echo "판단기준 : 불필요한 NFS 서비스 관련 데몬이 비활성화 되어 있는 경우" >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
		echo "1. 현황 : nfs|mountd|statd 서비스 확인" >> $CREATE_FILE 2>&1
		ps -ef | egrep "nfs|statd|mountd" | grep -v grep >> $CREATE_FILE 2>&1
		echo " " >> $CREATE_FILE 2>&1

	case $OS in
		SunOS)
			echo "1-2. 현황(Solaris 10버전 이상) : nfs|mountd|statd 서비스 확인" >> $CREATE_FILE 2>&1
			inetadm | egrep "nfs|statd|lockd" >> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1
			;;
		Linux)
			echo "2. 참고 : service nfs status 실행(NFS 프로세스의 Status 필드 inactive면 양호) " >> $CREATE_FILE 2>&1
			service nfs status >> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1
	esac
	echo " " >> $CREATE_FILE 2>&1
	echo "[END]" >> $CREATE_FILE 2>&1


echo "[U-25] NFS 접근통제"  
	echo "[U-25] NFS 접근통제"  >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
	echo "[START]"  >> $CREATE_FILE 2>&1
	echo "판단기준 : NFS 서비스를 사용하지 않거나 불필요하게 사용시 everyone 공유를 제한한경우 양호" >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
	case $OS in
		SunOS)
			if [ -f /etc/dfs/dfstab ]
			then
				echo "1. 현황 : /etc/dfs/dfstab 파일" >> $CREATE_FILE 2>&1
				cat /etc/dfs/dfstab >> $CREATE_FILE 2>&1
				echo " " >> $CREATE_FILE 2>&1
			else
				echo "1. 현황 : /etc/dfs/dfstab 파일이 없습니다." >> $CREATE_FILE 2>&1
				echo " " >> $CREATE_FILE 2>&1
			fi
			
			if [ -f /etc/dfs/sharetab ]
			then
				echo "2. 현황 : /etc/dfs/sharetab 파일" >> $CREATE_FILE 2>&1
				cat /etc/dfs/sharetab >> $CREATE_FILE 2>&1
				echo " " >> $CREATE_FILE 2>&1
			else
				echo "2. 현황 : /etc/dfs/sharetab 파일이 없습니다." >> $CREATE_FILE 2>&1
				echo " " >> $CREATE_FILE 2>&1
			fi
			;;
		Linux | AIX | HP-UX)
			echo "현황 : cat /etc/exports" >> $CREATE_FILE 2>&1
			cat /etc/exports >> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1
			;;
	esac
	echo " " >> $CREATE_FILE 2>&1
	echo "[END]" >> $CREATE_FILE 2>&1


echo "[U-26] automountd 제거"  
	echo "[U-26] automountd 제거"  >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
	echo "[START]"  >> $CREATE_FILE 2>&1
	echo "판단기준 : automountd 서비스가 구동중이지 않으면 양호" >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
		echo "1. 현황 : automountd 서비스 확인" >> $CREATE_FILE 2>&1
		ps -ef | egrep "automountd|autofs" | grep -v grep >> $CREATE_FILE 2>&1
		echo " " >> $CREATE_FILE 2>&1

	case $OS in
	SunOS)
		echo "2. 현황(Solaris 10버전 이상) : automountd 서비스 확인" >> $CREATE_FILE 2>&1
		svcs -a | egrep "auto" >> $CREATE_FILE 2>&1
		echo " " >> $CREATE_FILE 2>&1
		;;
	esac
	echo " " >> $CREATE_FILE 2>&1
	echo "[END]" >> $CREATE_FILE 2>&1


echo "[U-27] RPC 서비스 확인"
	echo "[U-27] RPC 서비스 확인" >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
	echo "[START]"  >> $CREATE_FILE 2>&1
	echo "판단기준 :  불필요한 RPC 관련 서비스가 존재하지 않으면 양호" >> $CREATE_FILE 2>&1
	echo "불필요한 RPC 서비스 >> rpc.cmsd|rpc.ttdbserverd|sadmind|rusersd|walld|sprayd|rstatd|rpc.nisd"	>> $CREATE_FILE 2>&1
	echo "불필요한 RPC 서비스 >> rpc.pcnfsd|rpc.statd|rpc.ypupdated|rpc.rquotad|kcms_server|cachefsd|rexd" >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1

	SERVICE_INETD="rpc.cmsd|rpc.ttdbserverd|sadmind|rusersd|walld|sprayd|rstatd|rpc.nisd|rpc.pcnfsd|rpc.statd|rpc.ypupdated|rpc.rquotad|kcms_server|cachefsd|rexd"
	SERVICE_INETD_LIST=( "rpc.cmsd" "rpc.ttdbserverd" "sadmind" "rusersd" "walld" "sprayd" "rstatd" "rpc.nisd" "rpc.pcnfsd" "rpc.statd" "rpc.ypupdated" "rpc.rquotad" "kcms_server" "cachefsd" "rexd" )
	echo "1. 현황 : /etc/inetd.conf 파일 확인" >> $CREATE_FILE 2>&1
	cat /etc/inetd.conf | egrep $SERVICE_INETD >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
	case $OS in
		Linux)		
			for file in $SERVICE_INETD_LIST
			do 
				echo "2. 현황 : /etc/xinetd.d/$file 파일 확인" >> $CREATE_FILE 2>&1
				cat /etc/xinetd.d/$file | grep -v '^#' 2>/dev/null >> $CREATE_FILE 2>&1
				echo " " >> $CREATE_FILE 2>&1
			done
			
			echo "3. 현황 : ls -al /etc/xinetd.d/*" >> $CREATE_FILE 2>&1
			ls -al /etc/xinetd.d/* >> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1
			;;
				
		SunOS)
			echo "1-2. 현황(Solaris 10버전 이상) : RPC 관련 데몬 확인" >> $CREATE_FILE 2>&1
			inetadm | grep rpc | egrep "ttdbserver|rex|rstat|rusers|spray|wall|rquota" >> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1
			;;
	esac
	echo " " >> $CREATE_FILE 2>&1
	echo "[END]" >> $CREATE_FILE 2>&1


echo "[U-28] NIS, NIS+ 점검"  
	echo "[U-28] NIS, NIS+ 점검"  >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
	echo "[START]"  >> $CREATE_FILE 2>&1
	echo "판단기준 : NIS, NIS+ 서비스를 비활성이면 양호" >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
		echo "1. 현황 : NIS 서비스 확인" >> $CREATE_FILE 2>&1
		ps -ef | egrep "ypserv|ypbind|ypxfrd|rpc.yppasswdd|rpc.ypupdated" | grep -v "grep" >> $CREATE_FILE 2>&1
		echo " " >> $CREATE_FILE 2>&1
	case $OS in
		SunOS)
			echo "1-2. 현황(Solaris 10버전 이상) : NIS 데몬 구동 확인" >> $CREATE_FILE 2>&1
			svcs -a | grep nis >> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1
			;;
	esac
	echo " " >> $CREATE_FILE 2>&1
	echo "[END]" >> $CREATE_FILE 2>&1

echo "[U-29] Tftp, talk 서비스 비 활성화"  
	echo "[U-29] Tftp, talk 서비스 비 활성화"  >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
	echo "[START]"  >> $CREATE_FILE 2>&1
	echo "판단기준 : tftp , tallk 서비스가 비활성이면 양호 " >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
		echo "1. 현황 : tftp,talk 서비스 확인" >> $CREATE_FILE 2>&1
		ps -ef | egrep "tftp|talk" | grep -v grep >> $CREATE_FILE 2>&1
		echo " " >> $CREATE_FILE 2>&1

		echo "2. 현황 : /etc/inetd.conf 주석처리여부 확인" >> $CREATE_FILE 2>&1
		cat /etc/inetd.conf | egrep "tftp|talk" >> $CREATE_FILE 2>&1
		echo " " >> $CREATE_FILE 2>&1
	case $OS in
		Linux)
			echo "판단기준 참고 : 서비스 확인시, disable=yes이면 양호)" >> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1
			echo "3-1. 현황 : cat /etc/xinetd.d/tftp" >> $CREATE_FILE 2>&1
			cat /etc/xinetd.d/tftp >> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1
			echo "3-2. 현황 : cat /etc/xinetd.d/talk" >> $CREATE_FILE 2>&1
			cat /etc/xinetd.d/talk >> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1
			echo "3-3. 현황 : cat /etc/xinetd.d/ntalk" >> $CREATE_FILE 2>&1
			cat /etc/xinetd.d/ntalk >> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1
			;;
		SunOS)
			echo "2-1. 현황(Solaris 10버전 이상) :  tftp,talk 데몬 구동 확인" >> $CREATE_FILE 2>&1
			inetadm | egrep "tftp|talk" >> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1
			;;
	esac
	echo " " >> $CREATE_FILE 2>&1
	echo "[END]" >> $CREATE_FILE 2>&1

echo "[U-30] Sendmail 버전 점검"
echo "[U-30] Sendmail 버전 점검"  >> $CREATE_FILE 2>&1
echo "[START]"  >> $CREATE_FILE 2>&1
echo "판단기준 : sendmail을 사용하지 않거나 버전이 최신버전(8.13.8 이상)인 경우 양호" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo "1. 현황 : sendmail 데몬 구동 확인" >> $CREATE_FILE 2>&1
ps -ef | grep sendmail >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

if [ -f /etc/mail/sendmail.cf ]
then
	echo "2-1. 현황 : /etc/mail/sendmail.cf에서 sendmail 버전확인" >> $CREATE_FILE 2>&1
	cat /etc/mail/sendmail.cf | grep DZ >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
else
	echo "2-1. 현황 :/etc/mail/sendmail.cf 파일이 없습니다." >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
fi

if [ -f /etc/sendmail.cf ]
then
	echo "2-2. 현황 : /etc/mail/sendmail.cf 에서 sendmail 버전확인" >> $CREATE_FILE 2>&1
	cat /etc/sendmail.cf | grep DZ >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
else
	echo "2-2. 현황 : /etc/sendmail.cf 파일이 없습니다." >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
fi

echo "3. 참고 : sendmail 포트 오픈 확인" >> $CREATE_FILE 2>&1
auto_tel(){
sleep 1;
}
auto_tel | telnet localhost 25 >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo "[END]" >> $CREATE_FILE 2>&1

echo "[U-31] 스팸 메일 릴레이 제한"  
echo "[U-31] 스팸 메일 릴레이 제한"  >> $CREATE_FILE 2>&1
echo "[START]"  >> $CREATE_FILE 2>&1
echo "판단기준 : SMTP 서비스를 사용하지 않거나, 릴레이 제한 설정을 했으면 양호" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo "1. 현황 : sendmail 데몬 구동 확인" >> $CREATE_FILE 2>&1
ps -ef | grep sendmail >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

if [ -f /etc/mail/sendmail.cf ]
then
	echo "2-1. 현황 : /etc/mail/sendmail.cf에서 sendmail 버전확인" >> $CREATE_FILE 2>&1
	cat /etc/mail/sendmail.cf | grep "R$\*" | grep "Relaying" >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
else
	echo "2-1. 현황 :/etc/mail/sendmail.cf 파일이 없습니다." >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
fi

if [ -f /etc/sendmail.cf ]
then
	echo "2-2. 현황 : /etc/mail/sendmail.cf 에서 sendmail 버전확인" >> $CREATE_FILE 2>&1
	cat /etc/sendmail.cf | grep "R$\*" | grep "Relaying" >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
else
	echo "2-2. 현황 : /etc/sendmail.cf 파일이 없습니다." >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
fi

echo " " >> $CREATE_FILE 2>&1
echo "[END]" >> $CREATE_FILE 2>&1

echo "[U-32] 일반 사용자의 sendmail 실행 방지"  
echo "[U-32] 일반 사용자의 sendmail 실행 방지"  >> $CREATE_FILE 2>&1
echo "[START]"  >> $CREATE_FILE 2>&1
echo "판단기준 : SMTP 서비스를 사용하지 않거나, 일반 사용자의 Sendmail 사용 방지 설정(PrivacyOptions=restrictqrun) 인 경우 양호" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo "1. 현황 : sendmail 데몬 구동 확인" >> $CREATE_FILE 2>&1
ps -ef | grep sendmail >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

if [ -f /etc/mail/sendmail.cf ]
then
	echo "2-1. 현황 : /etc/mail/sendmail.cf 에서 옵션 확인" >> $CREATE_FILE 2>&1
	cat /etc/mail/sendmail.cf | grep PrivacyOptions >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
else
	echo "2-1. 현황 :/etc/mail/sendmail.cf 파일이 없습니다." >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
fi

if [ -f /etc/sendmail.cf ]
then
	echo "2-2. 현황 : /etc/mail/sendmail.cf 에서 옵션 확인" >> $CREATE_FILE 2>&1
	cat /etc/sendmail.cf | grep PrivacyOptions >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
else
	echo "2-2. 현황 : /etc/sendmail.cf 파일이 없습니다." >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
fi
echo "[END]" >> $CREATE_FILE 2>&1

echo "[U-33] DNS 보안 버전 패치"  
	echo "[U-33] DNS 보안 버전 패치"  >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
	echo "[START]"  >> $CREATE_FILE 2>&1
	echo "판단기준 : DNS 서비스를 사용하지 않거나, 양호한 버전을 사용하고 있을 경우에 양호(8.4.6, 8.4.7, 9.2.8-P1, 9.3.4-P1, 9.3.5-P1, 9.4.1-P1, 9.4.2-P2, 9.5.0-P1, 9.5.0a6)" >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
	if [ `ps -ef | grep named | wc -l` -eq 0 ]
		then
			echo "1. 현황 : named 프로세스 없습니다."  >> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1
		else
			echo "1. 현황 : named 프로세스 확인" >> $CREATE_FILE 2>&1
			ps -ef | grep named | grep -v "grep"           >> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1
	fi
	case $OS in
	SunOS)
		echo "1-2. 현황(Solaris 10버전 이상) : : DNS 서비스 구동 확인" >> $CREATE_FILE 2>&1
		svcs -a | grep dns >> $CREATE_FILE 2>&1
		echo " " >> $CREATE_FILE 2>&1
		;;
	esac
	echo "2-1. 현황 : DNS 버전 확인(dig)" >> $CREATE_FILE 2>&1
	dig >> $CREATE_FILE 2>&1
	echo "2-2. 현황 : DNS 버전 확인(named -v)" >> $CREATE_FILE 2>&1
	named -v >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
	echo "[END]" >> $CREATE_FILE 2>&1


echo "[U-34] DNS Zone Transfer 설정"  
	echo "[U-34] DNS Zone Transfer 설정"  >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
	echo "[START]"  >> $CREATE_FILE 2>&1
	echo "판단기준 : DNS 서비스 미사용 또는 Zone Fransfer를 허가된 사용자에게만 허용한 경우" >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
		echo "1. 현황 : DNS 서비스 구동 확인" >> $CREATE_FILE 2>&1
		ps -ef | grep named | grep -v grep >> $CREATE_FILE 2>&1
		echo " " >> $CREATE_FILE 2>&1
	case $OS in
		SunOS)
			echo "1-2. 현황(Solaris 10버전 이상) : : DNS 서비스 구동 확인" >> $CREATE_FILE 2>&1
			svcs -a | egrep "dns" >> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1
			;;
	esac

	if [ -f /etc/named.conf ]
	then
		echo "2-1. /etc/named.conf | grep allow-transfer 확인" >> $CREATE_FILE 2>&1
		cat /etc/named.conf | grep 'allow-transfer' >> $CREATE_FILE 2>&1
		echo " " >> $CREATE_FILE 2>&1
	else
		echo "2-1. 현황 :/etc/named.conf이 없습니다." >> $CREATE_FILE 2>&1
		echo " " >> $CREATE_FILE 2>&1
	fi

	if [ -f /etc/bind/named.conf.options ]
	then
		echo "3-1. /etc/bind/named.conf.options | grep allow-transfer 확인" >> $CREATE_FILE 2>&1
		cat /etc/bind/named.conf.options | grep 'allow-transfer' >> $CREATE_FILE 2>&1
		echo " " >> $CREATE_FILE 2>&1
	else
		echo "3-2. 현황 : /etc/bind/named.conf.options이 없습니다." >> $CREATE_FILE 2>&1
		echo " " >> $CREATE_FILE 2>&1
	fi

	if [ -f /etc/named.boot ]
	then
		echo "4-1. /etc/named.boot | grep xfrnets 확인">> $CREATE_FILE 2>&1
		cat /etc/named.boot | grep xfrnets >> $CREATE_FILE 2>&1
		echo " " >> $CREATE_FILE 2>&1
	else
		echo "4-2. 현황 : /etc/named.boot 없습니다." >> $CREATE_FILE 2>&1
		echo " " >> $CREATE_FILE 2>&1
	fi
	echo " " >> $CREATE_FILE 2>&1
	echo "[END]" >> $CREATE_FILE 2>&1


echo "[U-35] 웹서비스 디렉터리 리스팅 제거"  
	echo "[U-35] 웹서비스 디렉터리 리스팅 제거"  >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
	echo "[START]"  >> $CREATE_FILE 2>&1
	echo "판단기준 : 디렉터리 검색 기능을 사용하지 않는 경우(httpd.conf 파일의 Directory 부분의 Options 지시자에 Indexes가 설정되어 있지 않으면 양호)" >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1

	if [ `ps -ef | grep httpd | awk '{print $8}' | grep -v grep | wc -l` -eq 0 ]
		then
			web1=0
			echo "1-1. 현황 : ps -ef | grep httpd 없습니다."  >> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1
		else
			web1=1
			echo "1-1. 참고 : httpd 구동 확인(PS)"  >> $CREATE_FILE 2>&1
			ps -ef | grep httpd | awk '{print $8}' | uniq  >> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1
	fi
	if [ `ps -ef | grep apache | awk '{print $8}' | grep -v grep | wc -l` -eq 0 ]
		then
			web2=0
			echo "1-2. 현황 : ps -ef | grep apache 없습니다."  >> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1
		else
			web2=1
			echo "1-2. 참고 : Apache 구동 확인(PS)"  >> $CREATE_FILE 2>&1
			ps -ef | grep apache | awk '{print $8}' | uniq  >> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1
	fi

	case $OS in
		SunOS)
			echo "1-3. 참고(Solaris 10버전 이상) : : Apache 서비스 구동 확인" >> $CREATE_FILE 2>&1
			svcs -a | grep apache >> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1
				;;
		Linux)
			echo "1-3. 현황 : Apache 상태 확인" >> $CREATE_FILE 2>&1
			service httpd status >> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1
			
			echo "1-4. 현황 : Apache 상태 확인(CentOS7 이상)" >> $CREATE_FILE 2>&1
			systemctl status httpd>> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1
			
			echo "1-5. 현황 : Apache 상태 확인(Ubuntu)" >> $CREATE_FILE 2>&1
			service apache2 status >> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1
				;;
	esac

	httpd_conf_=`find /etc -name httpd.conf`  >> $CREATE_FILE 2>&1
	httpd_conf_wc=`find /etc -name httpd.conf | wc -l`  >> $CREATE_FILE 2>&1
	apache_conf_=`find /etc -name apache2.conf`  >> $CREATE_FILE 2>&1
	apache_conf_wc=`find /etc -name apache2.conf | wc -l`  >> $CREATE_FILE 2>&1

	echo "2. 현황 : httpd.conf 파일 확인" >> $CREATE_FILE 2>&1
	echo "===================" >> $CREATE_FILE 2>&1

	if [ $httpd_conf_wc -gt 0 ];
	then	
			echo "1. 현황 : httpd_conf 파일 확인" >> $CREATE_FILE 2>&1
			
			for file in $httpd_conf_ 
			do
				echo $file >> $CREATE_FILE 2>&1
				echo " " >> $CREATE_FILE 2>&1
				cat $file | egrep -i "<Directory|Indexes|</Directory" >> $CREATE_FILE 2>&1
				echo "===================" >> $CREATE_FILE 2>&1
			done
	else	                                                                                 
		if [ $apache_conf_wc -gt 0 ];
		then	
			echo "1. 현황 : apache_conf 파일 확인" >> $CREATE_FILE 2>&1
			
			for file in $apache_conf_ 
			do
				echo $file >> $CREATE_FILE 2>&1
				echo " " >> $CREATE_FILE 2>&1
				cat $file | egrep -i "<Directory|Indexes|</Directory" >> $CREATE_FILE 2>&1
				echo "===================" >> $CREATE_FILE 2>&1
			done
		else
			echo " " >> $CREATE_FILE 2>&1
			echo "2. 현황 : httpd_conf 파일 없음 (양호)" >> $CREATE_FILE 2>&1
		fi
	fi

	echo " " >> $CREATE_FILE 2>&1
	echo "[END]" >> $CREATE_FILE 2>&1


echo "[U-36] 웹서비스 프로세스 권한 제한"  
	echo "[U-36] 웹서비스 프로세스 권한 제한"  >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
	echo "[START]"  >> $CREATE_FILE 2>&1
	echo "판단기준 : Apache 데몬이 root 권한으로 구동되지 않은 경우 양호" >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
	echo "1. 현황 : 구동여부는 U-51을 보고 판단" >> $CREATE_FILE 2>&1
	echo " "   >> $CREATE_FILE 2>&1
	echo "2. 현황 : httpd.conf 파일 확인" >> $CREATE_FILE 2>&1
	echo "===================" >> $CREATE_FILE 2>&1

	if [ $httpd_conf_wc -gt 0 ];
	then	
			echo "1. 현황 : httpd_conf 파일 확인" >> $CREATE_FILE 2>&1
			
			for file in $httpd_conf_ 
			do
				echo $file >> $CREATE_FILE 2>&1
				echo " " >> $CREATE_FILE 2>&1
				cat $file | grep -i "user" | grep -v "\#" | egrep -v "^LoadModule|LogFormat|IfModule|UserDir" >> $CREATE_FILE 2>&1
				cat $file | grep -i "group" | grep -v "\#" | egrep -v "^LoadModule|LogFormat|IfModule|UserDir" >> $CREATE_FILE 2>&1
				echo "===================" >> $CREATE_FILE 2>&1
			done
	else	                                                                                 
		if [ $apache_conf_wc -gt 0 ];
		then	
			echo "1. 현황 : apache_conf 파일 확인" >> $CREATE_FILE 2>&1
			
			for file in $apache_conf_ 
			do
				echo $file >> $CREATE_FILE 2>&1
				echo " " >> $CREATE_FILE 2>&1
				cat $file | grep -i "user" | grep -v "\#" | egrep -v "^LoadModule|LogFormat|IfModule|UserDir" >> $CREATE_FILE 2>&1
				cat $file | grep -i "group" | grep -v "\#" | egrep -v "^LoadModule|LogFormat|IfModule|UserDir" >> $CREATE_FILE 2>&1
				echo "===================" >> $CREATE_FILE 2>&1
			done
		else
			echo "2. 현황 : httpd_conf 파일 없음 (양호)" >> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1
		fi
	fi

	echo " " >> $CREATE_FILE 2>&1
	echo "[END]" >> $CREATE_FILE 2>&1


echo "[U-37] 웹서비스 상위 디렉터리 접근 금지"  
	echo "[U-37] 웹서비스 상위 디렉터리 접근 금지"  >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
	echo "[START]"  >> $CREATE_FILE 2>&1
	echo "판단기준 : 상위 디렉터리에 이동 제한을 설정한 경우(directory 부분의 AllowOverride None 설정이 아니면 양호)" >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1

	echo " " >> $CREATE_FILE 2>&1
	echo "1. 현황 : 구동여부는 U-51을 보고 판단" >> $CREATE_FILE 2>&1
	echo " "  >> $CREATE_FILE 2>&1
	echo "2. 현황 : httpd.conf 파일 확인" >> $CREATE_FILE 2>&1
	echo "===================" >> $CREATE_FILE 2>&1

	if [ $httpd_conf_wc -gt 0 ];
	then	
			echo "1. 현황 : httpd_conf 파일 확인" >> $CREATE_FILE 2>&1
			
			for file in $httpd_conf_ 
			do
				echo $file >> $CREATE_FILE 2>&1
				echo " " >> $CREATE_FILE 2>&1
				cat $file | egrep -i "<Directory|AllowOverride|</Directory" >> $CREATE_FILE 2>&1
				echo "===================" >> $CREATE_FILE 2>&1
			done
	else	                                                                                 
		if [ $apache_conf_wc -gt 0 ];
		then	
			echo "1. 현황 : apache_conf 파일 확인" >> $CREATE_FILE 2>&1
			
			for file in $apache_conf_ 
			do
				echo $file >> $CREATE_FILE 2>&1
				echo " " >> $CREATE_FILE 2>&1
				cat $file | egrep -i "<Directory|AllowOverride|</Directory" >> $CREATE_FILE 2>&1
				echo "===================" >> $CREATE_FILE 2>&1
			done
		else
			echo "2. 현황 : httpd_conf 파일 없음 (양호)" >> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1
		fi
	fi

	echo " " >> $CREATE_FILE 2>&1
	echo "[END]" >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
	
echo "[U-38] 웹서비스 불필요한 파일 제거"  
	echo "[U-38] 웹서비스 불필요한 파일 제거"  >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
	echo "[START]"  >> $CREATE_FILE 2>&1
	echo "판단기준 : Default로 생성되는 불필요한 파일이 제거되어 있는 경우 양호" >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
	#iname으로 대소문자 없이 찾아보자
	
	manual__wc=`find / -iname manual 2>/dev/null | grep apache | wc -l`  >> $CREATE_FILE 2>&1
	if [ $manual__wc -gt 0 ];
	then
		manual_=`find / -iname manual | grep apache`  >> $CREATE_FILE 2>&1
	fi
	
	cgi_bin_wc=`find / -iname cgi-bin 2>/dev/null | grep apache | wc -l`  >> $CREATE_FILE 2>&1
	if [ $cgi_bin_wc -gt 0 ];
	then
		cgi_bin=`find / -iname cgi-bin | grep apache`  >> $CREATE_FILE 2>&1
	fi
	
	if [ $manual__wc -gt 0 ];
	then
			echo "1. 현황 : manual 파일 출력" >> $CREATE_FILE 2>&1
			for file in $manual_ 
			do
				echo $file >> $CREATE_FILE 2>&1
				echo "===================" >> $CREATE_FILE 2>&1
			done
	else
			echo "1. 현황 : manual 파일 없음 (양호)" >> $CREATE_FILE 2>&1
	fi

	if [ $cgi_bin_wc -gt 0 ];
	then
			echo "2-1. 현황 : cgi-bin 파일 출력" >> $CREATE_FILE 2>&1
			echo "2-2. 참고 : default apache cgi-bin 경로는 OS 및 버전 마다 다르니 개인이 판단" >> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1
			for file in $cgi_bin
			do
				echo $file >> $CREATE_FILE 2>&1
				ls -al $file >> $CREATE_FILE 2>&1
				echo "===================" >> $CREATE_FILE 2>&1
			done
	else
			echo "2. 현황 : cgi-bin 디렉터리 없음 (양호)" >> $CREATE_FILE 2>&1
	fi
	echo "[END]" >> $CREATE_FILE 2>&1


echo "[U-39] 웹서비스 링크 사용 금지"  
	echo "[U-39] 웹서비스 링크 사용 금지"  >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
	echo "[START]"  >> $CREATE_FILE 2>&1
	echo "판단기준 : 심볼릭 링크 , aliases 사용을 제한한 경우(Options 지시자에서 심블릭 링크를 가능하게 하는 옵션인 FollowSymLinks가 제거된 경우 양호)" >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1

	if [ $httpd_conf_wc -gt 0 ];
	then	
			echo "1. 현황 : httpd_conf 파일 확인" >> $CREATE_FILE 2>&1
			
			for file in $httpd_conf_ 
			do
				echo $file >> $CREATE_FILE 2>&1
				echo " " >> $CREATE_FILE 2>&1
				cat $file | egrep -i "<Directory |FollowSymLinks|</Directory" >> $CREATE_FILE 2>&1
				echo "===================" >> $CREATE_FILE 2>&1
			done
	else	                                                                                 
		if [ $apache_conf_wc -gt 0 ];
		then
			echo "1. 현황 : httpd_conf 파일 확인" >> $CREATE_FILE 2>&1
			
			for file in $apache_conf_ 
			do
				echo $file >> $CREATE_FILE 2>&1
				echo " " >> $CREATE_FILE 2>&1
				cat $file | egrep -i "<Directory |FollowSymLinks|</Directory" >> $CREATE_FILE 2>&1
				echo "===================" >> $CREATE_FILE 2>&1
			done
		else
			echo "2. 현황 : httpd_conf 파일 없음 (양호)"                                                          >> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1
		fi
	fi

	echo " " >> $CREATE_FILE 2>&1
	echo "[END]" >> $CREATE_FILE 2>&1

echo "[U-40] 웹서비스 파일 업로드 및 다운로드 제한"  
	echo "[U-40] 웹서비스 파일 업로드 및 다운로드 제한"  >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
	echo "[START]"  >> $CREATE_FILE 2>&1
	echo "판단기준 참고 : 시스템에 따라 파일 업로드 및 다운로드에 대한 용량이 제한되어 있는 경우 양호" >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1

	if [ $httpd_conf_wc -gt 0 ];
	then	
			echo "1. 현황 : httpd_conf 파일 확인" >> $CREATE_FILE 2>&1
			
			for file in $httpd_conf_ 
			do
				echo $file >> $CREATE_FILE 2>&1
				echo " " >> $CREATE_FILE 2>&1
				cat $file | egrep -i "<Directory |LimitRequestBody|</Directory" >> $CREATE_FILE 2>&1
				echo "===================" >> $CREATE_FILE 2>&1
			done
	else	                                                                                 
		if [ $apache_conf_wc -gt 0 ];
		then	
			echo "1. 현황 : httpd_conf 파일 확인" >> $CREATE_FILE 2>&1
			
			for file in $apache_conf_ 
			do
				echo $file >> $CREATE_FILE 2>&1
				echo " " >> $CREATE_FILE 2>&1
				cat $file | egrep -i "<Directory |LimitRequestBody|</Directory" >> $CREATE_FILE 2>&1
				echo "===================" >> $CREATE_FILE 2>&1
			done
		else
			echo "2. 현황 : httpd_conf 파일 없음 (양호)"                                                          >> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1
		fi
	fi

	echo " " >> $CREATE_FILE 2>&1
	echo "[END]" >> $CREATE_FILE 2>&1


echo "[U-41] 웹 서비스 영역의 분리"  
	echo "[U-41] 웹 서비스 영역의 분리"  >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
	echo "[START]"  >> $CREATE_FILE 2>&1
	echo "판단기준 : DocumentRoot를 기본 디렉터리(/usr/local/apache/htdocs, /usr/local/apache2/htdocs, /var/www/html)가 아닌 별도의 디렉토리로 지정한 경우 양호" >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1

	echo "1. 현황 : httpd_conf 파일 내에 DocumentRoot 확인" >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
	if [ $httpd_conf_wc -gt 0 ];
	then	
			echo "1. 현황 : httpd_conf 파일 확인" >> $CREATE_FILE 2>&1
			
			for file in $httpd_conf_ 
			do
				echo $file >> $CREATE_FILE 2>&1
				echo " " >> $CREATE_FILE 2>&1
				cat $file | grep "DocumentRoot" | grep -v \# >> $CREATE_FILE 2>&1
				echo "===================" >> $CREATE_FILE 2>&1
			done
	else	                                                                                 
		if [ $apache_conf_wc -gt 0 ];
		then
			echo "1. 현황 : apache_conf 파일 확인" >> $CREATE_FILE 2>&1
			for file in $apache_conf_ 
			do
				echo $file >> $CREATE_FILE 2>&1
				echo " " >> $CREATE_FILE 2>&1
				cat $file | grep "DocumentRoot" >> $CREATE_FILE 2>&1
				echo "===================" >> $CREATE_FILE 2>&1
			done
		else
			echo "2. 현황 : httpd_conf 파일 없음 (양호)"                                                          >> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1
		fi
	fi

	echo " " >> $CREATE_FILE 2>&1
	echo "[END]" >> $CREATE_FILE 2>&1


echo "[U-60] SSH 원격접속 허용"  
	echo "[U-60] SSH 원격접속 허용"  >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
	echo "[START]"  >> $CREATE_FILE 2>&1
	echo "판단기준 : 원격 접속 시 SSH 프로토콜을 사용 했을 경우" >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
		if [ `ps -ef | grep sshd | grep -v "grep" | wc -l` -eq 0 ]
		then
			echo "1. 현황 : sshd 서비스 데몬이 동작하지 않습니다."  >> $CREATE_FILE 2>&1
		else
			echo "1. 현황 : ssh 서비스 확인(PS)" >> $CREATE_FILE 2>&1
			ps -ef | grep sshd | grep -v "grep"           >> $CREATE_FILE 2>&1
		fi
		echo " " >> $CREATE_FILE 2>&1	

	case $OS in
		SunOS)
			echo "1-2. 현황 : ssh 서비스 확인(SOL9 이하)" >> $CREATE_FILE 2>&1
			cat /etc/inetd.conf | grep ssh >> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1
			echo "1-3. 현황 : ssh 서비스 확인(SOL10 이상)" >> $CREATE_FILE 2>&1
			svcs -a | grep ssh >> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1
			;;
		Linux)
			echo "1-1. 현황 : ssh 서비스 확인" >> $CREATE_FILE 2>&1
			service sshd status >> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1
			echo "1-2. 현황 : ssh 서비스 확인(CentOS7)" >> $CREATE_FILE 2>&1
			systemctl status ssh >> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1
			;;
	esac
	echo " " >> $CREATE_FILE 2>&1
	echo "[END]" >> $CREATE_FILE 2>&1


echo "[U-61] FTP 서비스 확인"
	echo "[U-61] FTP 서비스 확인" >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
	echo "[START]"  >> $CREATE_FILE 2>&1
	echo "판단기준 : ftp 서비스가 비활성화 되어 있는 경우 양호  " >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1

		if [ `ps -ef | grep ftp | grep -v "grep" | wc -l` -eq 0 ]
		then
			echo "1. 현황 : ftp 프로세스 없음"  >> $CREATE_FILE 2>&1
		else
			echo "1. 현황 : ftp 프로세스 확인" >> $CREATE_FILE 2>&1
			ps -ef | grep ftp | grep -v "grep"           >> $CREATE_FILE 2>&1
		fi
		echo " " >> $CREATE_FILE 2>&1	

	case $OS in
		SunOS | AIX | HP-UX)
			echo "1-2. 현황 : ftp 서비스 확인(SOL9 이하/AIX/HP-UX)" >> $CREATE_FILE 2>&1
			cat /etc/inetd.conf | grep ftp >> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1
			echo "1-3. 현황 : ftp 서비스 확인(SOL10 이상)" >> $CREATE_FILE 2>&1
			svcs -a | grep ftp >> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1
			;;
	esac

	if [ -f /etc/xinetd.d/tftp ]
	then
		echo "2-1. 참고 : /etc/xinetd.d/tftp 파일" >> $CREATE_FILE 2>&1
		cat /etc/xinetd.d/tftp >> $CREATE_FILE 2>&1
		echo " " >> $CREATE_FILE 2>&1
	else
		echo "2-1. 참고 : /etc/xinetd.d/tftp 파일이 없습니다." >> $CREATE_FILE 2>&1
		echo " " >> $CREATE_FILE 2>&1
	fi

	if [ -f /etc/xinetd.d/vsftp ]
	then
		echo "2-2. 참고 : /etc/xinetd.d/vsftp 파일" >> $CREATE_FILE 2>&1
		cat /etc/xinetd.d/vsftp >> $CREATE_FILE 2>&1
		echo " " >> $CREATE_FILE 2>&1
	else
		echo "2-2. 참고 : /etc/xinetd.d/vsftp 파일이 없습니다." >> $CREATE_FILE 2>&1
		echo " " >> $CREATE_FILE 2>&1
	fi
	echo " " >> $CREATE_FILE 2>&1
	echo "[END]" >> $CREATE_FILE 2>&1


echo "[U-62] FTP계정 shell 제한"
	echo "[U-62] FTP계정 shell 제한" >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
	echo "[START]"  >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
	echo "판단기준 : ftp 서비스가 비활성화 또는 ftp 계정의 쉘이 /bin/false(솔라리스 /usr/bin/false) 또는 /sbin/nologin이면 양호  " >> $CREATE_FILE 2>&1
	echo "판단기준 참고 : ftp 서비스 상태는 59번 항목 참고" >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
	if [ `cat /etc/passwd | grep ftp | wc -l` -gt 0 ]
	then
		echo "1. 현황 : /etc/passwd | grep ftp" >> $CREATE_FILE 2>&1
		cat /etc/passwd | grep ftp >> $CREATE_FILE 2>&1
	else
		echo "1. ftp 프로세스가 없습니다." >> $CREATE_FILE 2>&1
	fi
	echo " " >> $CREATE_FILE 2>&1
	echo "[END]" >> $CREATE_FILE 2>&1

echo "[U-63] FTPusers 파일 소유자 및 권한설정"
	echo "[U-63] FTPusers 파일 소유자 및 권한설정" >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
	echo "[START]"  >> $CREATE_FILE 2>&1
	echo "판단기준 : ftpusers 파일 소유자가 root이면서 파일권한 640 이하일시 양호" >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1

	if [ -f /etc/ftpusers ]
	then
		echo "1-1. 현황(기본FTP/ProFTP) : /etc/ftpusers 파일" >> $CREATE_FILE 2>&1
		ls -al /etc/ftpusers >> $CREATE_FILE 2>&1
		echo " " >> $CREATE_FILE 2>&1
	else
		echo "1-1. 현황(기본FTP/ProFTP) : /etc/ftpusers 파일이 없습니다." >> $CREATE_FILE 2>&1
		echo " " >> $CREATE_FILE 2>&1
	fi
	if [ -f /etc/ftpd/ftpusers ]
	then
		echo "1-2 현황(기본FTP/ProFTP) : /etc/ftpd/ftpusers 파일" >> $CREATE_FILE 2>&1
		ls -al /etc/ftpd/ftpusers >> $CREATE_FILE 2>&1
		echo " " >> $CREATE_FILE 2>&1
	else
		echo "1-2. 현황(기본FTP/ProFTP) : /etc/ftpd/ftpusers 파일이 없습니다." >> $CREATE_FILE 2>&1
		echo " " >> $CREATE_FILE 2>&1
	fi
	if [ -f /etc/vsftpd/ftpusers ]
	then
		echo "1-3 현황(vsFTP) : /etc/vsftpd/ftpusers 파일" >> $CREATE_FILE 2>&1
		ls -al /etc/vsftpd/ftpusers >> $CREATE_FILE 2>&1
		echo " " >> $CREATE_FILE 2>&1
	else
		echo "1-3. 현황(vsFTP) : /etc/vsftpd/ftpusers 파일이 없습니다." >> $CREATE_FILE 2>&1
		echo " " >> $CREATE_FILE 2>&1
	fi
	if [ -f /etc/vsftpd/user_list ]
	then
		echo "1-4 현황(vsFTP) : /etc/vsftpd/user_list 파일" >> $CREATE_FILE 2>&1
		ls -al /etc/vsftpd/user_list >> $CREATE_FILE 2>&1
		echo " " >> $CREATE_FILE 2>&1
	else
		echo "1-4. 현황(vsFTP) : /etc/vsftpd/user_list 파일이 없습니다." >> $CREATE_FILE 2>&1
		echo " " >> $CREATE_FILE 2>&1
	fi
	if [ -f /etc/vsftpd.ftpusers ]
	then
		echo "1-5 현황(vsFTP) : /etc/vsftpd.ftpusers" >> $CREATE_FILE 2>&1
		ls -al /etc/vsftpd.ftpusers >> $CREATE_FILE 2>&1
		echo " " >> $CREATE_FILE 2>&1
	else
		echo "1-5. 현황(vsFTP) : /etc/vsftpd.ftpusers 파일이 없습니다." >> $CREATE_FILE 2>&1
		echo " " >> $CREATE_FILE 2>&1
	fi
	if [ -f /etc/vsftpd.user_list ]
	then
		echo "1-6 현황(vsFTP) : /etc/vsftpd.user_list" >> $CREATE_FILE 2>&1
		ls -al /etc/vsftpd.user_list >> $CREATE_FILE 2>&1
		echo " " >> $CREATE_FILE 2>&1
	else
		echo "1-6. 현황(vsFTP) : /etc/vsftpd.user_lists 파일이 없습니다." >> $CREATE_FILE 2>&1
		echo " " >> $CREATE_FILE 2>&1
	fi
	echo " " >> $CREATE_FILE 2>&1
	echo "[END]" >> $CREATE_FILE 2>&1


echo "[U-64] FTPusers 파일 설정"  
	echo "[U-64] FTPusers 파일 설정"  >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
	echo "[START]"  >> $CREATE_FILE 2>&1
	echo "판단기준 : root 주석 미처리 또는 rootlogin off 일경우 양호 " >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
	if [ -f /etc/ftpusers ]
	then
		echo "1-1 현황(기본FTP/ProFTP) : /etc/ftpusers 파일" >> $CREATE_FILE 2>&1
		cat /etc/ftpusers >> $CREATE_FILE 2>&1
		echo " " >> $CREATE_FILE 2>&1
	else
		echo "1-1. 현황(기본FTP/ProFTP) : /etc/ftpusers 파일이 없습니다." >> $CREATE_FILE 2>&1
		echo " " >> $CREATE_FILE 2>&1
	fi
	if [ -f /etc/ftpd/ftpusers ]
	then
		echo "1-2 현황(기본FTP/ProFTP) : /etc/ftpd/ftpusers 파일" >> $CREATE_FILE 2>&1
		cat /etc/ftpd/ftpusers >> $CREATE_FILE 2>&1
		echo " " >> $CREATE_FILE 2>&1
	else
		echo "1-2. 현황(기본FTP/ProFTP) : /etc/ftpd/ftpusers 파일이 없습니다." >> $CREATE_FILE 2>&1
		echo " " >> $CREATE_FILE 2>&1
	fi
	if [ -f /etc/vsftpd/ftpusers ]
	then
		echo "1-3 현황(vsFTP) : /etc/vsftpd/ftpusers 파일" >> $CREATE_FILE 2>&1
		cat  /etc/vsftpd/ftpusers >> $CREATE_FILE 2>&1
		echo " " >> $CREATE_FILE 2>&1
	else
		echo "1-3. 현황(vsFTP) : /etc/vsftpd/ftpusers 파일이 없습니다." >> $CREATE_FILE 2>&1
		echo " " >> $CREATE_FILE 2>&1
	fi
	if [ -f /etc/vsftpd/user_list ]
	then
		echo "1-4 현황(vsFTP) : /etc/vsftpd/user_list 파일" >> $CREATE_FILE 2>&1
		cat  /etc/vsftpd/user_list >> $CREATE_FILE 2>&1
		echo " " >> $CREATE_FILE 2>&1
	else
		echo "1-4. 현황(vsFTP) : /etc/vsftpd/user_list 파일이 없습니다." >> $CREATE_FILE 2>&1
		echo " " >> $CREATE_FILE 2>&1
	fi
	if [ -f /etc/vsftpd.ftpusers ]
	then
		echo "1-5 현황(vsFTP) : /etc/vsftpd.ftpusers" >> $CREATE_FILE 2>&1
		cat  /etc/vsftpd.ftpusers >> $CREATE_FILE 2>&1
		echo " " >> $CREATE_FILE 2>&1
	else
		echo "1-5. 현황(vsFTP) : /etc/vsftpd.ftpusers 파일이 없습니다." >> $CREATE_FILE 2>&1
		echo " " >> $CREATE_FILE 2>&1
	fi
	if [ -f /etc/vsftpd.user_list ]
	then
		echo "1-6 현황(vsFTP) : /etc/vsftpd.user_list" >> $CREATE_FILE 2>&1
		cat  /etc/vsftpd.user_list >> $CREATE_FILE 2>&1
		echo " " >> $CREATE_FILE 2>&1
	else
		echo "1-6. 현황(vsFTP) : /etc/vsftpd.user_list 파일이 없습니다." >> $CREATE_FILE 2>&1
		echo " " >> $CREATE_FILE 2>&1
	fi
	echo " " >> $CREATE_FILE 2>&1
	echo "[END]" >> $CREATE_FILE 2>&1


echo "[U-65] At 파일 소유자 및 권한 설정"  
	echo "[U-65] At 파일 소유자 및 권한 설정"  >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
	echo "[START]"  >> $CREATE_FILE 2>&1
	echo "판단기준 : 파일의 소유자가 root이면서 파일권한 640 이하면 양호 " >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
	case $OS in
		SunOS)
			echo "1. 현황 : at 접근제어 파일 확인" >> $CREATE_FILE 2>&1
			ls -l /etc/cron.d/at.* >> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1
			;;
		Linux)
			echo "1. 현황 : at 접근제어 파일 확인" >> $CREATE_FILE 2>&1
			ls -l /etc/at.* >> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1
			;;
		AIX | HP-UX)
			echo "1. 현황 : at 접근제어 파일 확인" >> $CREATE_FILE 2>&1
			ls -l /var/adm/cron/at* >> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1
			;;
	esac
	echo " " >> $CREATE_FILE 2>&1
	echo "[END]" >> $CREATE_FILE 2>&1

echo "[U-66] Snmp 서비스 구동 점검"
	echo "[U-66] Snmp 서비스 구동 점검"  >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
	echo "[START]"  >> $CREATE_FILE 2>&1
	echo "판단기준 : SNMP 서비스를 사용하지 않는 경우 양호 " >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
	if [ `ps -ef | grep snmp | wc -l` -gt 0 ] ########################################################의문점
	then
		echo "1. 현황 : SNMP 프로세스 확인" >> $CREATE_FILE 2>&1
		ps -ef | grep snmp | grep -v "grep" >> $CREATE_FILE 2>&1
		echo " " >> $CREATE_FILE 2>&1
	else
		echo "1. 현황 : snmp 프로세스가 없습니다." >> $CREATE_FILE 2>&1
		echo " " >> $CREATE_FILE 2>&1
	fi

	case $OS in
		SunOS)
			echo "1-2. 현황 : snmp 서비스 확인(SOL10 이상)" >> $CREATE_FILE 2>&1
			svcs -a | grep snmp >> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1
			;;
	esac
	echo " " >> $CREATE_FILE 2>&1
	echo "[END]" >> $CREATE_FILE 2>&1
	
echo "[U-67] Snmp 서비스 Community string의 복잡성 설정"
echo "[U-67] Snmp 서비스 Community string의 복잡성 설정"  >> $CREATE_FILE 2>&1
echo "[START]"  >> $CREATE_FILE 2>&1
echo "판단기준 : Community string이 public/private가 아니라면 양호 " >> $CREATE_FILE 2>&1
echo "1. 참고 : Snmp 서비스 상태는 65번 항목 참고" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
case $OS in
	SunOS)
		echo "2-1. 현황 : snmp 설정값 확인(SOL 9이하)" >> $CREATE_FILE 2>&1
		cat /etc/snmp/conf/snmpd.conf | grep community | grep -v \# >> $CREATE_FILE 2>&1
		echo " " >> $CREATE_FILE 2>&1
		echo "2-2. 현황 : snmp 설정값 확인(SOL 10)" >> $CREATE_FILE 2>&1
		cat /etc/sma/snmp/snmpd.conf | grep community | grep -v \# >> $CREATE_FILE 2>&1
		echo " " >> $CREATE_FILE 2>&1
		echo "2-3. 현황 : snmp 설정값 확인(SOL 11)" >> $CREATE_FILE 2>&1
		cat /etc/net-snmp/snmp/snmpd.conf | grep community | grep -v \# >> $CREATE_FILE 2>&1
		echo " " >> $CREATE_FILE 2>&1
		echo "2-4. 현황 : snmp 설정값 확인(SOL 10 이상)" >> $CREATE_FILE 2>&1
		svcs -a | grep snmp >> $CREATE_FILE 2>&1
		echo " " >> $CREATE_FILE 2>&1
		;;
	Linux)
		echo "2-1. 현황 : snmp 설정값 확인 /etc/snmpd/snmpd.conf" >> $CREATE_FILE 2>&1
		cat /etc/snmpd/snmpd.conf | grep community | grep -v \# >> $CREATE_FILE 2>&1
		echo " " >> $CREATE_FILE 2>&1
		echo "2-2. 현황 : snmp 설정값 확인 /etc/snmp/conf/snmpd.conf" >> $CREATE_FILE 2>&1
		cat /etc/snmp/conf/snmpd.conf | grep community | grep -v \# >> $CREATE_FILE 2>&1
		echo " " >> $CREATE_FILE 2>&1
		;;
	AIX)
		echo "2-1 snmp 설정값 확인 /etc/snmpd.conf" >> $CREATE_FILE 2>&1
		cat /etc/snmpd.conf | grep community | grep -v \# >> $CREATE_FILE 2>&1
		echo " " >> $CREATE_FILE 2>&1		
		echo "2-2. 현황 : snmp 설정값 확인 /etc/snmpd/snmpd.conf" >> $CREATE_FILE 2>&1
		cat /etc/snmpd/snmpd.conf | grep community | grep -v \# >> $CREATE_FILE 2>&1
		echo " " >> $CREATE_FILE 2>&1
		echo "2-3. 현황 : snmp 설정값 확인 etc/snmp/conf/snmpd.conf" >> $CREATE_FILE 2>&1
		cat /etc/snmp/conf/snmpd.conf | grep community | grep -v \# >> $CREATE_FILE 2>&1
		echo " " >> $CREATE_FILE 2>&1
		echo "2-4. 현황 : snmp 설정값 확인 /etc/snmpdv3.conf" >> $CREATE_FILE 2>&1
		cat /etc/snmpdv3.conf | grep community | grep -v \# >> $CREATE_FILE 2>&1
		echo " " >> $CREATE_FILE 2>&1
		;;
	HP-UX)
		echo "2-1 snmp 설정값 확인 /etc/snmpd.conf" >> $CREATE_FILE 2>&1
		cat /etc/snmpd.conf | grep community | grep -v \# >> $CREATE_FILE 2>&1
		echo " " >> $CREATE_FILE 2>&1		
		echo "2-2. 현황 : snmp 설정값 확인 /etc/snmpd/snmpd.conf" >> $CREATE_FILE 2>&1
		cat /etc/snmpd/snmpd.conf | grep community | grep -v \# >> $CREATE_FILE 2>&1
		echo " " >> $CREATE_FILE 2>&1
		echo "2-3. 현황 : snmp 설정값 확인 etc/snmp/conf/snmpd.conf" >> $CREATE_FILE 2>&1
		cat /etc/snmp/conf/snmpd.conf | grep community | grep -v \# >> $CREATE_FILE 2>&1
		echo " " >> $CREATE_FILE 2>&1
		;;
esac
echo " " >> $CREATE_FILE 2>&1
echo "[END]" >> $CREATE_FILE 2>&1


echo "[U-68] 로그온 시 경고 메시지 제공"  
	echo "[U-68] 로그온 시 경고 메시지 제공"  >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
	echo "[START]"  >> $CREATE_FILE 2>&1
	echo "판단기준 : 로그온 메시지가 설정되어 있지 않을경우 취약" >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1

	case $OS in
		SunOS)
			echo "1. 현황 : 서버 로그인 메시지 설정 /etc/motd " >> $CREATE_FILE 2>&1
			cat /etc/motd >> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1
			echo "2-1. 참고 : TELNET 서비스 상태는 1번 항목 참고" >> $CREATE_FILE 2>&1
			echo "2-2. 참고 : netstat -na | grep 23" >> $CREATE_FILE 2>&1
			netstat -na | grep *.23 >> $CREATE_FILE 2>&1
			echo "2-3. 현황 : Telnet 배너 설정 /etc/default/telnetd " >> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1
			cat /etc/default/telnetd | grep BANNER >> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1
			echo "3-1. 참고 : FTP 서비스 상태는 60번 항목 참고" >> $CREATE_FILE 2>&1
			echo "3-2. 참고 : netstat -na | grep 21" >> $CREATE_FILE 2>&1
			netstat -na | grep *.21 >> $CREATE_FILE 2>&1
			echo "3-3. 현황 : TFP 배너 설정 /etc/default/ftpd " >> $CREATE_FILE 2>&1
			cat /etc/default/ftpd | grep BANNER >> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1
			echo "4-1. 참고 : SMTP 서비스 상태는 48번 항목 참고" >> $CREATE_FILE 2>&1
			echo "4-2. 참고 : netstat -na | grep 21" >> $CREATE_FILE 2>&1
			netstat -na | grep *.161 >> $CREATE_FILE 2>&1
			echo "4-3. 현황 : SMTP 배너 설정 /etc/mail/sendmail.cf " >> $CREATE_FILE 2>&1
			cat /etc/mail/sendmail.cf | grep -i "GreetingMessage" >> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1
			echo "5-1. 참고 : DNS 서비스 상태는 50번 항목 참고" >> $CREATE_FILE 2>&1
			echo "5-2. 참고 : netstat -na | grep 53" >> $CREATE_FILE 2>&1
			netstat -na | grep *.53 >> $CREATE_FILE 2>&1
			echo "5-3. 현황 : DNS 배너 설정 /etc/named.conf " >> $CREATE_FILE 2>&1
			cat /etc/named.conf >> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1
			;;
		Linux)
			echo "1. 현황 : issue 확인" >> $CREATE_FILE 2>&1
			ls -al /etc/issue >> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1
			cat /etc/issue >> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1
			echo "2. 현황 : issue.net 확인 " >> $CREATE_FILE 2>&1
			ls -al /etc/issue.net >> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1
			cat /etc/issue.net >> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1
			echo "3. 현황 : /etc/motd 확인" >> $CREATE_FILE 2>&1
			ls -al /etc/motd >> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1
			cat /etc/motd >> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1		
			;;
		AIX)
			echo "1. 현황 : 서버 로그인 메시지 설정 /etc/motd " >> $CREATE_FILE 2>&1
			cat /etc/motd >> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1
			echo "2-1. 참고 : TELNET 서비스 상태는 1번 항목 참고" >> $CREATE_FILE 2>&1
			echo "2-2. 참고 : netstat -na | grep 23" >> $CREATE_FILE 2>&1
			etstat -na | grep *.23 >> $CREATE_FILE 2>&1
			echo "2-3. 현황 : Telnet 배너 설정 /etc/security/login.cfg " >> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1
			cat /etc/security/login.cfg >> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1
			echo "3-1. 참고 : FTP 서비스 상태는 60번 항목 참고" >> $CREATE_FILE 2>&1
			echo "2-2. 참고 : netstat -na | grep 21" >> $CREATE_FILE 2>&1
			etstat -na | grep *.21 >> $CREATE_FILE 2>&1
			echo "3-3. 현황 : TFP 배너 설정 /etc/default/ftpd " >> $CREATE_FILE 2>&1
			#cat /etc/default/ftpd | grep BANNER >> $CREATE_FILE 2>&1
			#echo " " >> $CREATE_FILE 2>&1
			echo "4-1. 참고 : SMTP 서비스 상태는 48번 항목 참고" >> $CREATE_FILE 2>&1
			echo "4-2. 참고 : netstat -na | grep 161" >> $CREATE_FILE 2>&1
			etstat -na | grep *.161 >> $CREATE_FILE 2>&1
			echo "4-3. 현황 : SMTP 배너 설정 /etc/mail/sendmail.cf " >> $CREATE_FILE 2>&1
			cat /etc/mail/sendmail.cf | grep -i "GreetingMessage" >> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1
			echo "5-1. 참고 : DNS 서비스 상태는 50번 항목 참고" >> $CREATE_FILE 2>&1
			echo "5-2. 참고 : netstat -na | grep 53" >> $CREATE_FILE 2>&1
			etstat -na | grep *.53 >> $CREATE_FILE 2>&1
			echo "5-3. 현황 : DNS 배너 설정 /etc/named.conf " >> $CREATE_FILE 2>&1
			cat /etc/named.conf >> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1
			;;
		HP-UX)
			echo "1. 현황 : 서버 로그인 메시지 설정 /etc/motd " >> $CREATE_FILE 2>&1
			cat /etc/motd >> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1
			echo "2-1. 참고 : TELNET 서비스 상태는 1번 항목 참고" >> $CREATE_FILE 2>&1
			echo "2-2. 참고 : netstat -na | grep 23" >> $CREATE_FILE 2>&1
			etstat -na | grep *.23 >> $CREATE_FILE 2>&1
			echo "2-3. 현황 : Telnet 배너 설정 /etc/issue.net" >> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1
			cat /etc/issue.net >> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1
			echo "3-1. 참고 : FTP 서비스 상태는 60번 항목 참고" >> $CREATE_FILE 2>&1
			echo "3-2. 참고 : netstat -na | grep 21" >> $CREATE_FILE 2>&1
			etstat -na | grep *.21 >> $CREATE_FILE 2>&1
			echo "3-3. 현황 : TFP 배너 설정 /etc/default/ftpd " >> $CREATE_FILE 2>&1
			cat /etc/vsftpd/vsftpd.conf | grep banner >> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1
			echo "4-1. 참고 : SMTP 서비스 상태는 48번 항목 참고" >> $CREATE_FILE 2>&1
			echo "4-2. 참고 : netstat -na | grep 161" >> $CREATE_FILE 2>&1
			etstat -na | grep *.161 >> $CREATE_FILE 2>&1
			echo "4-3. 현황 : SMTP 배너 설정 /etc/mail/sendmail.cf " >> $CREATE_FILE 2>&1
			cat /etc/mail/sendmail.cf | grep -i "GreetingMessage" >> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1
			echo "5-1. 참고 : DNS 서비스 상태는 50번 항목 참고" >> $CREATE_FILE 2>&1
			echo "5-2. 참고 : netstat -na | grep 53" >> $CREATE_FILE 2>&1
			etstat -na | grep *.53 >> $CREATE_FILE 2>&1
			echo "5-3. 현황 : DNS 배너 설정 /etc/named.conf " >> $CREATE_FILE 2>&1
			cat /etc/named.conf >> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1
			;;
	esac
	echo " " >> $CREATE_FILE 2>&1
	echo "[END]" >> $CREATE_FILE 2>&1

echo "[U-69] NFS 설정파일 접근권한"  
	echo "[U-69] NFS 설정파일 접근권한"  >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
	echo "[START]"  >> $CREATE_FILE 2>&1
	echo "판단기준 : NFS 접근제어 설정파일의 소유자가 root 이고, 권한이 644 이하 일경우 양호" >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
	case $OS in
		SunOS)
			echo "1-1. 현황 : /etc/dfs/dfstab 접근권한 확인 " >> $CREATE_FILE 2>&1
			ls -al /etc/dfs/dfstab >> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1
			echo "1-2. 현황 :/etc/dfs/sharetab 접근권한 확인 " >> $CREATE_FILE 2>&1
			ls -al /etc/dfs/sharetab >> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1
			;;
		Linux)
			echo "현황 : /etc/exports 확인" >> $CREATE_FILE 2>&1
			ls -al /etc/exports >> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1
			cat /etc/exports >> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1
			;;
		AIX)
			echo "1. 현황 : /etc/exports 접근권한 확인 " >> $CREATE_FILE 2>&1
			ls -al /etc/exports >> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1
			;;
		HP-UX)
			echo "1-1. 현황 : /etc/exports 접근권한 확인 " >> $CREATE_FILE 2>&1
			ls -al /etc/exports >> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1
			echo "1-2. 현황 : /etc/dfs/dfstab 접근권한 확인 " >> $CREATE_FILE 2>&1
			ls -al /etc/dfs/dfstab >> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1\
			echo "1-3. 현황 : /etc/dfs/sharetab 접근권한 확인 " >> $CREATE_FILE 2>&1
			ls -al /etc/dfs/sharetab >> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1
			;;
	esac
	echo " " >> $CREATE_FILE 2>&1
	echo "[END]" >> $CREATE_FILE 2>&1

echo "[U-70] Expn, vrfy 명령어 제한"
echo "[U-70] Expn, vrfy 명령어 제한" >> $CREATE_FILE 2>&1
echo "[START]"  >> $CREATE_FILE 2>&1
echo "판단기준 : SMTP 서비스 미사용 또는 PrivacyOptions=goaway(noexpn,novrfy)를 포함하고 있을경우 양호 " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

echo "1. 참고 : SMTP 서비스 상태는 48번 항목 참고" >> $CREATE_FILE 2>&1
case $OS in
	SunOS | HP-UX | Linux)
		echo "2. 현황 :/etc/mail/sendmail.cf 접근권한 확인 " >> $CREATE_FILE 2>&1
		grep -v '^ *#' /etc/mail/sendmail.cf | grep PrivacyOptions >> $CREATE_FILE 2>&1
		echo " " >> $CREATE_FILE 2>&1
		;;
	AIX)
		echo "2. 현황 :/etc/sendmail.cf 접근권한 확인 " >> $CREATE_FILE 2>&1
		grep -v '^ *#' /etc/sendmail.cf | grep PrivacyOptions >> $CREATE_FILE 2>&1
		echo " " >> $CREATE_FILE 2>&1
		;;
esac
echo " " >> $CREATE_FILE 2>&1
echo "[END]" >> $CREATE_FILE 2>&1

echo "[U-71] Apache 웹 서비스 정보 숨김"  
	echo "[U-71] Apache 웹 서비스 정보 숨김"  >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
	echo "[START]"  >> $CREATE_FILE 2>&1
	echo "판단기준 : ServerTokens Prod 설정이 없는 경우 Default 설정(ServerTokens Full)이 적용됨,ServerTokens Prod 설정인 경우 양호" >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1

	if [ $httpd_conf_wc -gt 0 ];
	then	
			echo "1. 현황 : httpd_conf 파일 확인" >> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1
			for file in $httpd_conf_ 
			do
				echo $file >> $CREATE_FILE 2>&1
				echo " " >> $CREATE_FILE 2>&1
				cat $file | egrep -i "ServerTokens|ServerSignature" >> $CREATE_FILE 2>&1
				echo "===================" >> $CREATE_FILE 2>&1
			done
	else	                                                                                 
		if [ $apache_conf_wc -gt 0 ];
		then	
			echo "1. 현황 : apache_conf 파일 확인" >> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1
			for file in $apache_conf_ 
			do
				echo $file >> $CREATE_FILE 2>&1
				echo " " >> $CREATE_FILE 2>&1
				cat $file | egrep -i "ServerTokens|ServerSignature" >> $CREATE_FILE 2>&1
				echo "===================" >> $CREATE_FILE 2>&1
			done
		else
			echo " " >> $CREATE_FILE 2>&1
			echo "1. 현황 : httpd_conf 파일 없음 (양호)" >> $CREATE_FILE 2>&1
		fi
	fi

	echo " " >> $CREATE_FILE 2>&1
	echo "[END]" >> $CREATE_FILE 2>&1

echo "[U-42] 최신 보안패치 및 벤더 권고사항 적용"  
	echo "[U-42] 최신 보안패치 및 벤더 권고사항 적용"  >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
	echo "[START]"  >> $CREATE_FILE 2>&1
	echo "판단기준 : kernel 패치 버전 확인" >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
	case $OS in
		SunOS)
			echo "1. 현황 : cat /etc/release" >> $CREATE_FILE 2>&1
			cat /etc/release >> $CREATE_FILE 2>&1
			echo "2-1. 현황(SOL10 이하에서만 가능) : showrev -p" >> $CREATE_FILE 2>&1
			showrev -p >> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1
			echo "2-2. 현황(SOL11에서만 가능) : pkg info kernel" >> $CREATE_FILE 2>&1
			pkg info kernel >> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1
			;;
		Linux)
			echo "1. 현황 : 패치 확인" >> $CREATE_FILE 2>&1
			rpm -qa | grep "kernel" >> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1
			echo "2. 현황 : uname -r" >> $CREATE_FILE 2>&1
			uname -r >> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1
			echo "3. 현황 : cat /etc/*release* | grep -i Linux" >> $CREATE_FILE 2>&1
			cat /etc/*release* | grep -i linux >> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1
			;;
		AIX)
			echo "1. 현황 : 패치확인" >> $CREATE_FILE 2>&1
			lslpp -La >> $CREATE_FILE 2>&1
			instfix -iv | grep ML >> $CREATE_FILE 2>&1
			
			echo " " >> $CREATE_FILE 2>&1
			;;
		HP-UX)
			echo "1. 현황 : 패치확인" >> $CREATE_FILE 2>&1
			swlist -l product >> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1
			;;
	esac
	echo " " >> $CREATE_FILE 2>&1
	echo "[END]" >> $CREATE_FILE 2>&1

echo "[U-43] 로그의 정기적 검토 및 보고"  
	echo "[U-43] 로그의 정기적 검토 및 보고"  >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
	echo "[START]"  >> $CREATE_FILE 2>&1
	echo "판단기준 참고 : InterView " >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
	echo "[END]" >> $CREATE_FILE 2>&1

echo "[U-72] 정책에 따른 시스템 로깅 설정"  
	echo "[U-72] 정책에 따른 시스템 로깅 설정"  >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
	echo "[START]"  >> $CREATE_FILE 2>&1
	echo "판단기준 : alert,info에 대해서 파일에 로그가 남도록 설정되어 있다면 양호" >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
		echo "1. 현황 : syslog (PS)" >> $CREATE_FILE 2>&1
		ps -ef | grep 'syslog' | grep -v 'grep' >> $CREATE_FILE 2>&1
		echo " " >> $CREATE_FILE 2>&1
		
	if [ -f /etc/syslog.conf ] 
	then
		echo "2. 현황 : /etc/syslog.conf" >> $CREATE_FILE 2>&1
		ls -al /etc/syslog.conf >> $CREATE_FILE 2>&1
		cat /etc/syslog.conf | grep -v '^#' >> $CREATE_FILE 2>&1
	else
		echo "2. 현황 : /etc/syslog.conf 파일 없음" >> $CREATE_FILE 2>&1
	fi
	echo " " >> $CREATE_FILE 2>&1

	if [ -f /etc/rsyslog.conf ] 
	then
		echo "3. 현황 : /etc/rsyslog.conf" >> $CREATE_FILE 2>&1
		ls -al /etc/rsyslog.conf >> $CREATE_FILE 2>&1
		cat /etc/rsyslog.conf | grep -v '^#'  >> $CREATE_FILE 2>&1
	else
		echo "3. 현황 : /etc/rsyslog.conf 파일 없음" >> $CREATE_FILE 2>&1
	fi
	echo " " >> $CREATE_FILE 2>&1
	case $OS in
		Linux)
			if [ -f /etc/rsyslog.d/50-default.conf ] 
			then
				echo "4. [Ubuntu]현황 : /etc/rsyslog.d/50-default.conf" >> $CREATE_FILE 2>&1
				ls -al /etc/rsyslog.d/50-default.conf >> $CREATE_FILE 2>&1
				cat /etc/rsyslog.d/50-default.conf | grep -v '^#'  >> $CREATE_FILE 2>&1
			else
				echo "4. [Ubuntu]현황 : /etc/rsyslog.conf 파일 없음" >> $CREATE_FILE 2>&1
			fi
	esac

	echo " " >> $CREATE_FILE 2>&1
	echo "[END]" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo "======================================================================================================" >> $CREATE_FILE 2>&1
echo "======================================================================================================" >> $CREATE_FILE 2>&1
date   >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo "UNIX/Linux Security Check END" >> $CREATE_FILE 2>&1
echo "===============================================================" >> $CREATE_FILE 2>&1
echo "☞ UNIX 스크립트 작업이 완료되었습니다."  >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo "☞ 스크립트 결과 파일을 보안담당자에게 전달 바랍니다."  >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo "☞ 스크립트 관련 오류 및 문의사항은 (주)한국통신인터넷기술 직원에게 부탁드립니다."  >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo "☞ 감사합니다."  >> $CREATE_FILE 2>&1
echo "===============================================================" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo ">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>" >> $CREATE_FILE 2>&1
echo "Reference info." >> $CREATE_FILE 2>&1
echo "<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo "****************************************************************************************************" >> $CREATE_FILE 2>&1
echo "****************************************   INFO_CHKSTART   *************************************" >> $CREATE_FILE 2>&1
echo "****************************************************************************************************" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

echo "==============================" >> $CREATE_FILE 2>&1
echo "System Information Query Start" 							  >> $CREATE_FILE 2>&1
echo "==============================" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

echo "--------------------------------------   Kernel Information   --------------------------------------" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
uname -a >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo "----------------------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

echo "----------------------------------------   IP Information   ----------------------------------------" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
ifconfig -a >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo "----------------------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

echo "----------------------------------------   Network Status   ----------------------------------------" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
netstat -an | egrep -i "LISTEN|ESTABLISHED" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo "----------------------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

echo "-------------------------------------   Routing Information   --------------------------------------" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
netstat -rn >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo "----------------------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

echo "---------------------------------------   Process Status   -----------------------------------------" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
ps -ef >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo "----------------------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

echo "------------------------------------------   User Env   --------------------------------------------" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
env >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo "----------------------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

echo "============================" >> $CREATE_FILE 2>&1
echo "System Information Query End" 							   >> $CREATE_FILE 2>&1
echo "============================" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

echo "****************************************************************************************************" >> $CREATE_FILE 2>&1
echo "*****************************************   INFO_CHKEND   **************************************" >> $CREATE_FILE 2>&1
echo "****************************************************************************************************" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo ">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>" >> $CREATE_FILE 2>&1
echo "<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<" >> $CREATE_FILE 2>&1

