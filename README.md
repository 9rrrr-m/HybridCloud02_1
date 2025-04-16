# [하이브리드 클라우드] Ansible 세팅

## 환경 설정

### 네트워크 설정

- (Ansible PC)

  ```
  VMnet0:  bridge
  VMnet1:  192.168.1.0/24 (실제 부여 VMnet10)
  ```

- (내부 연결 시나리오)

  ```
  Route & WAF VM
    NIC1(VMnet0) : IP: 172.16.6.51/24, GW: 172.16.6.254, DNS: 8.8.8.8
    NIC2(VMnet1) : IP: 192.168.1.110/24
    
  LB VM
    NIC1(VMnet1) : IP: 192.168.1.200/24, GW: 192.168.1.110, DNS: 8.8.8.8
    
  Web1 VM
    NIC1(VMnet1) : IP: 192.168.1.104/24, GW: 192.168.1.110, DNS: 8.8.8.8

  Web2 VM
    NIC1(VMnet1) : IP: 192.168.1.105/24, GW: 192.168.1.110, DNS: 8.8.8.8

  Ansible Control VM (관리 노드)
    NIC1(VMnet1) : IP: 192.168.1.102/24, GW: 192.168.1.110, DNS: 8.8.8.8
  ```

- 환경: **ansible-navigator** 사용
    - ansible 제어 노드의 루트 파일 시스템이 존재하는 하드디스크 용량은 **60G**로 세팅.
    - ansible galaxy 홈페이지에서 **fedora-linux_system_roles-1.95.6.tar.gz 파일**을 다운 받아둔다.
        - 다운로드: [https://galaxy.ansible.com/ui/repo/published/fedora/linux_system_roles/](https://galaxy.ansible.com/ui/repo/published/fedora/linux_system_roles/)
        
        
  ```
  💡 GitHub에 로컬 레포지토리 구축용으로 실습에 필요한 파일들을 공개해두었습니다. 필요하신 분들은 tar.gz 파일을 사전에 다운 받지 않으셔도 레포지토리에 해당 소스 파일이 포함되어 있으니 그 파일을 사용하셔도 됩니다.
    ```
  → 아래 사전 작업 하단 참고
        
        
    
    - 사전 작업: 로컬 레포지토리 생성
        
        ```bash
        # (root 사용자) (pw: centos)
        dnf -y install httpd mod_ssl
        systemctl enable --now httpd
        
        # 로컬 레포지토리에 파일 준비
        mkdir /var/www/html/collections
        firefox https://galaxy.ansible.com/ui/repo/published/fedora/linux_system_roles/
        cp ~/Downloads/fedora-linux_system_roles-1.95.6.tar.gz /var/www/html/collections/
        ```
        
- vscode 설치
  - Manage - Settings
    - Auto Save: afterDelay
    - Font Size: 16
    - Tab Size: 2
    - Word Wrap: on
  - Extension install
    - Ansible
    - indent-rainbow

---


# 환경 구성

- Ansible 설치 및 구성 - ansible navigator
    - 기본 환경 세팅(ansible-navigator)
        - GitHub repository에 작업을 자동화 시켜 두었습니다. → https://github.com/9rrrr-m/Ansible_ENV_setting
        (호스트 파일 등 세부적인 내용은 인프라 설계 조건에 맞게 수정해서 사용)
        
        ```bash
        # (root로 작업)
        # ansible 계정 생성
        useradd -G wheel ansible
        echo 'ansible' | passwd --stdin ansible
        
        # ansible 사용자에게 비밀번호 없이 sudo 명령어 사용 권한 부여
        echo 'ansible  ALL=(ALL)  NOPASSWD: ALL' > /etc/sudoers.d/ansible
        
        ------------------------------------------------------------------
        # ansible 사용자로 로그인
        
        # ansible-navigator 프로그램 설치
        sudo dnf -y install python3-pip
        python3 -m pip install ansible-navigator --user
        
        # alias 설정
        vi ~/.bashrc
        --------------------------------------------------------------------------------
        export PATH="$HOME/.local/bin:$PATH"
        export PS1='\[\e[34;1m\][\u@\h\[\e[33;1m\] \w]\$ \[\e[m\]'
        
        #
        # Ansible alias
        #
        alias ans="ansible"
        alias anp="ansible-playbook"
        alias anx="ansible-galaxy"
        alias anv="ansible-vault"
        alias ann="ansible-navigator run -m stdout"
        alias ansfs="ansible localhost -m setup -a 'filter=ansible_*' | grep -i -A 2 $1"
        --------------------------------------------------------------------------------
        . ~/.bashrc
        
        # ande 쉘 프로그램
        mkdir bin
        vi ~/bin/ande
        -----------------------------------------------
        ansible-doc $1 | sed -n '/^EXAMPLES/,$p' | more
        -----------------------------------------------
        chmod +x ~/bin/ande
        
        # ~/.vimrc 설정
        vi ~/.vimrc
        -------------------------------------------------
        syntax on
        autocmd FileType yaml setlocal ai nu sw=2 ts=2 et
        -------------------------------------------------
        
        # ~/.ansible-navigator.yml playbook-artifact 생성 false 설정
        vi ~/.ansible-navigator.yml
        ---------------------------
        ansible-navigator:
          playbook-artifact:
            enable: false
        ---------------------------
        
        # /etc/hosts 설정
        sudo vi /etc/hosts
        ------------------------------------------------------------------------------
        127.0.0.1   localhost localhost.localdomain localhost4 localhost4.localdomain4
        ::1         localhost localhost.localdomain localhost6 localhost6.localdomain6
        
        # ansible configuration
        192.168.1.110  waf.example.com   waf
        192.168.1.200  lb.example.com  lb
        192.168.1.104  web1.example.com  web1
        192.168.1.105  web2.example.com  web2
        192.168.1.102  control.example.com  control
        ------------------------------------------------------------------------------
        
        # ssh 공개키 생성
        ssh-keygen
        
        # ssh 공개키 배포 -> 관리 노드 root
        ssh-copy-id root@waf
        ssh-copy-id root@lb
        ssh-copy-id root@web1
        ssh-copy-id root@web2
        
        # ssh 공개키 배포 -> 제어 노드 root
        ssh-copy-id root@control
        
        # project 디렉토리 생성
        mkdir project && cd project
        ```
        
    - vi ansible.cfg
        
        ```yaml
        [defaults]
        inventory = inventory
        roles_path = roles:/home/ansible/.ansible/roles:/usr/share/ansible/roles:/etc/ansible/roles
        collections_paths = collections:/home/ansible/.ansible/collections:/usr/share/ansible/collections:/etc/ansible/collections
        
        [privilege_escalation]
        become = true
        become_user = root
        become_method = sudo
        ```
        
    - vi inventory
        
        ```yaml
        [waf]
        waf.example.com
        
        [lb]
        lb.example.com
        
        [web]
        web1.example.com
        web2.example.com
        ```
        
    - 각 관리 노드에 ansible 사용자 생성, sudo 권한 부여 및 공개키 배포
        - vi ansible-ENV-setting.yml
        
        ```yaml
        ---
        - name: ansible-navigator env setting
          hosts: all
          vars:
            pw: ansible
          tasks:
            - name: useradd ansible
              ansible.builtin.user:
                name: ansible
                password: "{{ pw | password_hash('sha512') }}"
                groups: wheel
                
            - name: Deploy /etc/sudoers.d/ansible
              ansible.builtin.copy:
                content: "ansible  ALL=(ALL)  NOPASSWD: ALL\n"
                dest: /etc/sudoers.d/ansible
                mode: '0644'
            
            - name: Deploy ssh public key
              ansible.builtin.authorized_key:
                user: ansible
                state: present
                key: "{{ lookup('file', '~/.ssh/id_rsa.pub') }}"
        ```
        
    - (실행) `ann ansible-ENV-setting.yml`

- 시스템 역할 사용 - time syncronization
    
    시스템 역할 패키지를 설치하고 다음과 같은 **/home/ansible/project/time_sync.yml** 이라는 플레이북을 생성합니다.
    
    - 모든 관리형 노드에서 실행
    - **timesync 역할**을 사용
    - 현재 활성 NTP 제공업체를 사용하도록 역할 구성
    - 시간 서버 **kr.pool.ntp.org**를 사용하도록 역할 구성
    - **iburst 매개 변수**를 활성화하도록 역할 구성
    - [참고] ansible-navigator로 실행 시 RHEL 시스템 역할 패키지 내의 모듈과 롤을 인식 못함
              (현재 디렉토리를 컨테이너화 하여 컨테이너 환경에서 실행되므로)
        - ansible galaxy 홈페이지에서 **fedora-linux_system_roles-1.95.6.tar.gz 파일**을 **/var/www/html/collections** 위치에 다운 받아 사용
        - 일반적이라면 `sudo dnf -y install rhel-system-roles` 수행해서 설치 후 사용
        - **BUT!** ansible-navigator 환경이라면 현재 폴더 외부 경로에 설치된 rhel-system-roles는 사용 불가
    - 로컬 레포지토리에서 fedora-linux_system_roles-1.95.6.tar.gz 파일 다운받아 사용
        
        ```bash
        # 로컬에서 컬렉션 다운받아 설치
        mkdir collections
        vi collections/requirements.yml
        ----------------------------------------------------------------------------------
        ---
        collections:
          - name: http://192.168.1.102/collections/fedora-linux_system_roles-1.95.6.tar.gz
        ----------------------------------------------------------------------------------
        anx collection install -r collections/requirements.yml -p collections
        ```
        
        - 외부 인터넷 연결이 된다면 ansible-galaxy에서 바로 받아도 됨
            
            `anx collection install fedora.linux_system_roles -p collections/`
            
    
    - vi time_sync.yml
        
        ```yaml
        ---
        - name: Time synchronization
          hosts: all
          tasks:
            - name: Set timezone
              community.general.timezone:
                name: Asia/Seoul  # tzselect
            
            - name: Timesync
              ansible.builtin.include_role:
                name: fedora.linux_system_roles.timesync
              vars:
                timesync_ntp_servers:
                  - hostname: kr.pool.ntp.org
                    iburst: true
        ```
        
        - (참고 문서 경로) collections/ansible_collections/fedora/linux_system_roles/roles/timesync/README.md

- 역할 생성 및 사용 - waf 설정, web 설정
    
    다음 요구 사항에 맞게 /home/ansible/project/roles에서 **waf, apache** 역할 생성
    
    - httpd/firewalld 패키지 설치, httpd/firewalld 서비스가 현재 뿐만 아니라 부팅 시에도 활성화, http/https 서비스 포트가 방화벽에 등록되고 작동 시작
    - 방화벽이 활성화되며 해당 웹 서버에 대한 엑세스를 허용하는 규칙으로 실행
    - 템플릿 파일 index.html.j2가 존재하며 다음 출력이 있는 /var/www/html/index.html 파일을 생성하는데 사용됨
    - **HOSTNAME**이 관리형 노드의 정규화된 도메인 이름이며, **IPADDRESS**가 관리형 노드의 IP주소
        - **Welcome to HOSTNAME on IPADDRESS.**
    
    다음과 같이 두 역할을 사용하는 /home/ansible/project/newrole.yml이라는 플레이북을 생성한다.
    
    - 플레이북은 각각 waf role - waf / apache role - web 호스트 그룹에 있는 호스트에서 실행된다.
    
    [역할 생성]
    
    - waf role
        - anx init roles/waf
        - vi roles/waf/tasks/main.yml
            
            ```yaml
            ---
            # tasks file for roles/waf
            - name: Install packages
              ansible.builtin.dnf:
                name: "{{ pkg }}"
                state: present
                
            - name: Start and enable service
              ansible.builtin.systemd:
                name: "{{ item }}"
                state: started
                enabled: true
              loop: "{{ svc }}"
              
            - name: Firewall port open
              ansible.posix.firewalld:
                service: "{{ item }}"
                permanent: true
                immediate: true
                state: enabled
              loop: "{{ fw_rule }}"
            ```
            
        - vi roles/waf/vars/main.yml
            
            ```yaml
            ---
            # vars file for roles/waf
            pkg:
              - firewalld
            svc:
              - firewalld
            fw_rule:
              - http
              - https
            ```
            
    - apache role
        - anx init roles/apache
        - vi roles/apache/tasks/main.yml
            
            ```yaml
            ---
            # tasks file for roles/apache
            - name: Install packages
              ansible.builtin.dnf:
                name: "{{ pkg }}"
                state: present
                
            - name: Start and enable service
              ansible.builtin.systemd:
                name: "{{ item }}"
                state: started
                enabled: true
              loop: "{{ svc }}"
              
            - name: Deploy index.html.j2 template
              ansible.builtin.template:
                src: templates/index.html.j2
                dest: /var/www/html/index.html
                mode: '0644'
            ```
            
        - vi roles/apache/vars/main.yml
            
            ```yaml
            ---
            # vars file for roles/apache
            pkg:
              - httpd
              - mod_ssl
            svc:
              - httpd
            ```
            
        - vi roles/apache/templates/index.html.j2
            - (검색) ansfs ipv4
            
            ```yaml
            Welcome to {{ ansible_fqdn }} on {{ ansible_default_ipv4['address'] }}.
            ```
            
        - vi newrole.yml
            
            ```yaml
            ---
            - name: Use waf role
              hosts: waf
              roles:
                - waf
            
            - name: Use apache role
              hosts: web
              roles:
                - apache
            ```
            
        - (test)
            
            `ans waf -m shell -a 'firewall-cmd --list-all'` 
            
            `curl web1` 
            
            `curl web2`
            

- 호스트 파일 생성
    - /home/ansible/project/templates에 초기 템플릿 파일을 생성
        - /etc/hosts와 동일한 형식으로 각 인벤토리 호스트에 대한 줄이 포함된 파일을 생성하는 데 사용할 수 있도록 템플릿을 작성
    - 모든 호스트 그룹의 호스트에서 파일 /etc/hosts를 생성하도록 이 템플릿을 사용하는 /home/ansible/project/hosts.yml 이라는 플레이북을 생성
    - /etc/hosts 파일의 소유자는 root 이고, 그룹은 root, 퍼미션은 rw-r--r-- 설정
    - 플레이북이 실행되면 모든 호스트 그룹의 호스트에 파일 /etc/hosts에 각 관리형 호스트에 대한 내용이 들어가야 함
    
    - vi inventory
        
        ```yaml
        [waf]
        waf.example.com ansible_ssh_host=192.168.1.110
        
        [lb]
        lb.example.com ansible_ssh_host=192.168.1.200
        
        [web]
        web1.example.com ansible_ssh_host=192.168.1.104
        web2.example.com ansible_ssh_host=192.168.1.105
        ```
        
    - `mkdir templates`
    - vi templates/hosts.j2
        - (매직변수 확인) `ans localhost -m debug -a 'var=groups["all"]'`
                                  `ans localhost -m debug -a 'var=hostvars["waf"]'`
        
        ```yaml
        127.0.0.1   localhost localhost.localdomain localhost4 localhost4.localdomain4
        ::1         localhost localhost.localdomain localhost6 localhost6.localdomain6
        
        {% for i in groups['all'] %}
        {{ hostvars[i].ansible_ssh_host }}  {{ hostvars[i].inventory_hostname }}  {{ hostvars[i].inventory_hostname_short }}
        {% endfor %}
        ```
        
    - vi hosts.yml
        
        ```yaml
        ---
        - name: Deploy hosts.j2
          hosts: all
          tasks:
            - name: Using template module
              ansible.builtin.template:
                src: templates/hosts.j2
                dest: /etc/hosts
                owner: root
                group: root
                mode: '0644'
        ```
        
    - (확인) `ans waf -m shell -a "cat /etc/hosts"`

- Ansible Galaxy role 사용하기 - lb 설정, php 테스트 페이지
    
    (작업1) 아래 조건을 만족하는 **/home/ansible/project/roles/requirements.yml** 라는 요구 사항 파일을 만든다. 이 파일은 Ansible Galaxy를 사용하여 역할을 다운로드하고 **/home/ansible/project/roles** 디렉토리 하위에 역할을 설치한다.
    
    - https://github.com/geerlingguy/ansible-role-haproxy/archive/1.3.1.tar.gz
    이 역할의 이름은 balancer이어야 한다.
    - https://github.com/buluma/ansible-role-php.git
    이 역할의 이름은 phpinfo이어야 한다.
    
    (작업2) 다음 요구 사항을 갖는 /home/ansible/project/loadbalancer.yml 이름의 playbook을 생성한다.
    
    - lb 호스트 그룹에서 실행되며 balancer role을 사용하는 play가 포함되어야 한다. 이 role은 web 호스트 그룹 내의 호스트 사이에서 웹 서버 요청을 로드 밸런싱하는 서비스를 구성한다.
        - 예) http://lb.example.com/ 을 브라우징하면 다음 출력이 생성
        **Welcome to web1.example.com on 192.168.1.104**
            
            브라우저를 다시 로드하면 대체 웹 서버에서 출력을 생성
            **Welcome to web2.example.com on 192.168.1.105**
            
    - web 호스트 그룹에서 실행되며 phpinfo role을 사용하는 play가 포함되어야 한다. web 호스트 그룹 내의 호스트에서 /hello.php URL로 브라우징하면 다음 출력이 생성된다.
    **Hello PHP World from FQDN**
        - 여기서 FQDN은 호스트의 완전한 도메인 이름
        - 예1) http://web1.example.com/hello.php 을 브라우징하면 다음 출력이 생성
        **Hello PHP World from web1.example.com**
        - 예2) http://web2.example.com/hello.php 를 브라우징하면, PHP 구성의 여러 세부 정보와 함께 다음과 같은 출력 생성
        **Hello PHP World from web2.example.com**
            - PHP 구성의 다양한 세부 정보와 설치된 PHP 버전을 포함하여 출력
    
    [작업 내용]
    
    - vi roles/requirements.yml
        
        ```yaml
        ---
        - name: balancer
          src: https://github.com/geerlingguy/ansible-role-haproxy/archive/1.3.1.tar.gz
          
        - name: phpinfo
          src: https://github.com/buluma/ansible-role-php.git
        ```
        
    - `anx install -r roles/requirements.yml -p roles/`
    - (수정) vi roles/balancer/defaults/main.yml
        
        ```bash
        # List of backend servers.
        haproxy_backend_servers:
          - name: web1
            address: 192.168.1.104:80
          - name: web2
            address: 192.168.1.105:80
        ```
        
    - (추가) vi roles/phpinfo/tasks/main.yml
        
        ```yaml
        - name: Deploy hello.php
          ansible.builtin.copy:
            dest: /var/www/html/hello.php
            content: '<?php echo "Hello PHP world from {{ ansible_fqdn }}"; phpinfo(); ?>'
        ```
        
    - vi loadbalancer.yml
        
        ```yaml
        ---
        - name: Include role phpinfo
          hosts: web
          roles:
            - phpinfo
          
        - name: Include role balancer
          hosts: lb
          roles:
            - balancer
        ```
        
    - (확인) `curl http://lb.example.com/`
              `firefox http://web1.example.com/hello.php`
              `firefox http://web2.example.com/hello.php`

- 암호 자격 증명 모음 생성 - locker.yml, secret.txt
    
    ansible 자격 증명 모음을 생성하여 다음과 같이 사용자 암호를 저장한다.
    
    - 자격 증명 모음의 이름: /home/ansible/project/**locker.yml**
    - 자격 증명 모음에는 이름이 있는 한 개의 변수가 포함됨
        - pw 변수의 값: test
    - 자격 증명 모음을 암호화하고 해독하는 암호는 **soldesk1.**
    - locker.yml 플레이북을 실행할 때 암호가 필요하면 이 암호는 secret.txt 파일에 저장
    
    - vi locker.yml
        
        ```yaml
        pw: test
        ```
        
    - vi secret.txt
        
        ```yaml
        soldesk1.
        ```
        
    - `chmod 600 secret.txt`
    - `anv encrypt locker.yml --vault-password-file=secret.txt`
    - cat locker.yml
        
        ```yaml
        $ANSIBLE_VAULT;1.1;AES256
        66663932643662636365373463663661356564653530366538663361623733333261393434636432
        6431636138326337373864393665366630623738663237340a373334613631393934346365656563
        37353632346264393735633162306539626561613633626536333930333564646366616464666535
        6639383339663435340a366361363464356261366532333265356332656662383766346164396365
        3265
        ```
        

- 사용자 계정 생성 - test
    - /home/ansible/project/userlist.yml 생성한 후 사용자/그룹 목록으로 사용한다.
    - /home/ansible/project/users.yml 실행하여 사용자를 추가한다.
        - 암호 자격 증명 모음을 사용한다.
            - locker.yml
    
    - vi userlist.yml
        
        ```yaml
        ---
        users:
          - username: test
            groups: wheel
            password_expire_max: 9999
        ```
        
    - vi users.yml
        
        ```yaml
        ---
        - name: Create test user
          hosts: all
          vars_files:
            - locker.yml
            - userlist.yml
          tasks:
            - name: Create user
              ansible.builtin.user:
                name: "{{ users[0].username }}"
                password: "{{ pw | password_hash('sha512') }}"
                password_expire_max: "{{ users[0].password_expire_max }}"
                groups: "{{ users[0].groups }}"
                state: present
        
            - name: Deploy /etc/sudoers.d/username
              ansible.builtin.copy:
                content: "test  ALL=(ALL)  NOPASSWD: ALL\n"
                dest: /etc/sudoers.d/{{ users[0].username }}
                mode: '0644'
        ```
        
    - `ann users.yml --vault-password-file=secret.txt`

- 사용자 계정 삭제 - test2
    - 생성된 test2 계정을 삭제한다.
    
    - vi userdel.yml
        
        ```yaml
        ---
        - name: Delete user
          hosts: all
          vars:
            - del_user: test2
          tasks:
            - name: Remove the user {{ del_user }}
              ansible.builtin.user:
                name: "{{ del_user }}"
                state: absent
                remove: true
        ```
        

- 하드웨어 보고서 생성 - hwreport-hostname.txt
    
    다음 정보를 수집하기 위해 모든 관리형 노드에서 /root/hwreport.txt 라는 출력 파일을 생성하는 /home/ansible/project/hwreport.yml 플레이북을 생성한다.
    
    - 인벤토리 호스트 이름
    - 총 메모리(MB)
    - BIOS 버전
    - 디스크 장치 sda, sdb, sdc의 크기
    - 출력 파일의 각 행에는 단일 행에는 key=value 쌍이 포함됨
    
    플레이북에서 수행될 세부 요건은 아래와 같다.
    
    - hwreport.empty 파일을 사용하여 각 관리 대상 호스트에 /root/hwreport.txt 파일 이름으로 저장
    - 올바른 값으로 /root/hwreport.txt를 수정
    - 디스크 하드웨어 항목이 없는 경우 연결된 값이 NONE으로 설정됨

      | 수정전 - hwreport.txt | 수정후 - hwreport.txt |
      | --- | --- |
      | HOST=inventory hostname | HOST=ansible3 |
      | BIOS=bios version | BIOS=6.00 |
      | MEMORY=total memory in mb | MEMORY=777 |
      | SD**A**_DISK_SIZE=disk size | SD**A**_DISK_SIZE=40.00 GB |
      | SD**B**_DISK_SIZE=disk size | SD**B**_DISK_SIZE=1.00 GB | 
      | SD**C**_DISK_SIZE=disk size | SD**C**_DISK_SIZE=NONE |

    - 각 관리 대상 호스트에 수정된 /root/hwreport.txt 파일을 제어노드의 ~/project/report 디렉토리에 다음과 같은 이름으로 결과 파일을 수집한다.
        
      ```
      ~/project
        +-- report
            +-- hwreport-waf.txt
            +-- hwreport-lb.txt
            +-- hwreport-web1.txt
            +-- hwreport-web2.txt
      ```

    (사전 준비) templates/hwreport.empty 템플릿 파일 작성
    
    - vi templates/hwreport.empty
        
        ```yaml
        HOST=inventory hostname
        BIOS=bios version
        MEMORY=total memory in mb
        SDA_DISK_SIZE=disk size
        SDB_DISK_SIZE=disk size
        SDC_DISK_SIZE=disk size
        ```
        
    - vi hwreport.yml
        
        ```yaml
        ---
        - name: Hardware report
          hosts: all
          tasks:
            - name: Deploy hwreport.txt
              ansible.builtin.template:
                src: templates/hwreport.empty
                dest: /root/hwreport.txt
                mode: '0644'
        
            - name: Edit file - Host
              ansible.builtin.lineinfile:
                path: /root/hwreport.txt
                regexp: '^HOST='
                line: "HOST={{ ansible_hostname }}"
        
            - name: Edit file - BIOS
              ansible.builtin.lineinfile:
                path: /root/hwreport.txt
                regexp: '^BIOS='
                line: "BIOS={{ ansible_bios_version }}"
        
            - name: Edit file - MEMORY
              ansible.builtin.lineinfile:
                path: /root/hwreport.txt
                regexp: '^MEMORY='
                line: "MEMORY={{ ansible_memtotal_mb }}"
        
            - name: Edit file - SDA_DISK_SIZE
              ansible.builtin.lineinfile:
                path: /root/hwreport.txt
                regexp: '^SDA_DISK_SIZE='
                line: |
                  {% if ansible_devices['sda'] is defined %}
                  SDA_DISK_SIZE={{ ansible_devices['sda']['size'] }}
                  {% else %}
                  SDA_DISK_SIZE=NONE
                  {% endif %}
        
            - name: Edit file - SDB_DISK_SIZE
              ansible.builtin.lineinfile:
                path: /root/hwreport.txt
                regexp: '^SDB_DISK_SIZE='
                line: |
                  {% if ansible_devices['sdb'] is defined %}
                  SDB_DISK_SIZE={{ ansible_devices['sdb']['size'] }}
                  {% else %}
                  SDB_DISK_SIZE=NONE
                  {% endif %}
        
            - name: Edit file - SDC_DISK_SIZE
              ansible.builtin.lineinfile:
                path: /root/hwreport.txt
                regexp: '^SDC_DISK_SIZE='
                line: SDC_DISK_SIZE={{ ansible_devices.sdc.size | default('NONE') }}
        
            - name: Fetch hwreport.txt
              ansible.builtin.fetch:
                src: /root/hwreport.txt
                dest: "report/hwreport-{{ ansible_hostname }}.txt"
                flat: true
        ```
        
        - (검색) `ansfs <hostname>`

- 아카이브 하기 - web server 백업
    
    backup.yml 플레이북을 “/home/ansible/project/“ 경로에 다음과 같은 조건으로 생성
    
    - 전체 호스트 그룹에서 수행
    - “/var/www/html/” 디렉토리의 tar 파일 생성
    - ansible control node에 tar 파일 복사하여 수집
        - results/backup-**FQDN**.tar.gz
    
    - vi backup.yml
        
        ```yaml
        ---
        - name: Backup host node
          hosts: all
          tasks:
            - name: Create tar file
              community.general.archive:
                path: /var/www/html/
                dest: /root/backup.tar.gz
                format: gz
        
            - name: Fetch the backup file to control node
              ansible.builtin.fetch:
                src: "/root/backup.tar.gz"
                dest: "results/backup-{{ ansible_fqdn }}.tar.gz"
                flat: true
        ```
        
    - (결과 확인) `tree results`
        
        ```bash
        [ansible@control ~/project]$ tree results
        results
        ├── backup-web1.example.com.tar.gz
        └── backup-web2.example.com.tar.gz
        
        0 directories, 2 files
        ```
        

- 파일 콘텐츠 수정 - /etc/issue
    
    다음과 같이 /home/ansible/project/issue.yml 이라는 플레이북을 생성한다.
    
    - 플레이북은 모든 인벤토리 호스트에서 실행된다.
    - 플레이북은 /etc/issue의 콘텐츠를 다음과 같은 한줄의 텍스트로 대체한다.
    - waf 호스트 그룹의 호스트에서 이 줄은 다음과 같다. **WAF**
    - lb 호스트 그룹의 호스트에서 이 줄은 다음과 같다. **LB**
    - web 호스트 그룹의 호스트에서 이 줄은 다음과 같다. **WEB server**
    
    - vi inventory
        
        ```yaml
        [waf]
        waf.example.com ansible_ssh_host=192.168.1.110
        
        [lb]
        lb.example.com ansible_ssh_host=192.168.1.200
        
        [web]
        web1.example.com ansible_ssh_host=192.168.1.104
        web2.example.com ansible_ssh_host=192.168.1.105
        
        [waf:vars]
        issue_content=WAF
        
        [lb:vars]
        issue_content=LB
        
        [web:vars]
        issue_content="WEB server"
        ```
        
    - vi issue.yml
        
        ```yaml
        ---
        - name: Change issue content
          hosts: all
          tasks:
            - name: Using copy module
              ansible.builtin.copy:
                content: "{{ issue_content }}\n"
                dest: /etc/issue
                owner: root
                group: root
                mode: '0644'
        ```
        
    - (다른 방법) `mkdir group_vars`  - 그룹 변수 사용
        - vi group_vars/waf
            
            ```yaml
            issue_content: WAF
            ```
            
        - vi group_vars/lb
            
            ```yaml
            issue_content: LB
            ```
            
        - vi group_vars/web
            
            ```yaml
            issue_content: WEB server
            ```
            
    - (확인) `ans all -m shell -a "cat /etc/issue"`

- SELinux 설정
    
    각 노드의 SELinux를 enforcing으로 변경한다.
    
    - vi selinux.yml
        
        ```yaml
        ---
        - name: Set SELinux enforcing
          hosts: all
          tasks:
            - name: Config /etc/selinux/config
              ansible.builtin.lineinfile:
                path: /etc/selinux/config
                regexp: '^SELINUX='
                line: 'SELINUX=enforcing'
                state: present
        
            - name: Reboot
              ansible.builtin.reboot:
        ```
        
    - (다른 방법) vi selinux2.yml  - collection 사용
        
        ```yaml
        ---
        - name: Set SELinux enforcing
          hosts: all
          tasks:
            - name: Config SELinux
              ansible.builtin.include_role:
                name: fedora.linux-system-roles.selinux
              vars:
                selinux_policy: targeted
                selinux_state: enforcing
        ```
        
    - (Ad-hoc 이용한 방법) `ans all -m selinux -a 'policy=targeted state=enforcing'`

- 반복 작업 설정 - cronjob
    
    (date) 다음과 같은 조건을 갖는 /home/ansible/project/cronjob.yml 파일을 생성한다.
    
    - 다음 작업은 web 그룹에서만 실행됨
    - **ansible** 사용자의 잡 설정으로 지정
    - 잡 이름은 **datejob**
    - 매시간 2번(0분, 30분)씩 평일(월~금)에만 date 명령의 출력 결과를 /home/ansible/datefile 저장
    - /home/ansible/datefile에는 date 명령의 출력 결과가 지속적으로 남겨져 있어야 함
    
    - vi cronjob.yml
        
        ```yaml
        ---
        - name: Create cronjob
          hosts: web
          tasks:
            - name: Configure datejob
              ansible.builtin.cron:
                name: datejob
                cron_file: datejob
                user: ansible
                minute: '0,30'
                weekday: '1-5'
                job: "date >> /home/ansible/datefile"
        ```
        
    
    (logger) 다음과 같은 조건을 갖는 /home/ansible/project/cronjob2.yml 파일을 생성한다.
    
    - 다음 작업은 web 그룹에서만 실행됨
    - **ansible** 사용자의 잡 설정으로 지정
    - 잡 이름은 **loggerjob**
    - 2분마다 logger "Ansible logger in progress"를 실행
    
    - vi cronjob2.yml
        
        ```yaml
        ---
        - name: Create cronjob2
          hosts: web
          tasks:
            - name: Configure loggerjob
              ansible.builtin.cron:
                name: loggerjob
                cron_file: loggerjob
                user: ansible
                minute: '*/2'
                job: 'logger "Ansible logger in progress"'
        ```
        
        - (확인) `ans web -m shell -a 'cat /var/log/messages | grep Ansible'`
            
            ```bash
            web1.example.com | CHANGED | rc=0 >>
            Mar 11 10:46:01 web1 ansible[3215]: Ansible logger in progress
            Mar 11 10:48:01 web1 ansible[3786]: Ansible logger in progress
            Mar 11 10:50:01 web1 ansible[3983]: Ansible logger in progress
            web2.example.com | CHANGED | rc=0 >>
            Mar 11 10:46:01 web2 ansible[3428]: Ansible logger in progress
            Mar 11 10:48:01 web2 ansible[3999]: Ansible logger in progress
            Mar 11 10:50:02 web2 ansible[4198]: Ansible logger in progress
            ```
            
    
    (delete cronjob) 다음과 같은 조건을 갖는 /home/ansible/project/delete_cronjob.yml 파일을 생성한다.
    
    - 다음 작업은 web 그룹에서만 실행됨
    - **ansible** 사용자의 잡 설정으로 지정
    - 잡 이름이 **loggerjob**인 작업을 삭제
    
    - vi delete_cronjob.yml
        
        ```yaml
        ---
        - name: Delete cronjob
          hosts: web
          tasks:
            - name: Remove loggerjob
              ansible.builtin.cron:
                name: loggerjob
                cron_file: loggerjob
                user: ansible
                state: absent
        ```
        

- 시스템 런레벨(default.target) 변경
    - 다음과 같은 조건을 갖는 multi_target.yml 파일을 작성한다.
        - 모든 노드는 multi-user.target를 사용하도록 설정
    
    - vi multi_target.yml
        
        ```yaml
        ---
        - name: Set default target
          hosts: all
          tasks:
            - name: Configure multi-user.target
              ansible.builtin.shell:
                cmd: "systemctl set-default multi-user.target"
              changed_when: false
        ```
        
    
    - 다음과 같은 조건을 갖는 graphical_target.yml 파일을 작성한다.
        - 모든 노드는 graphical.target를 사용하도록 설정
    
    - vi graphical_target.yml
        
        ```yaml
        ---
        - name: Set default target
          hosts: all
          tasks:
            - name: Configure graphical.target
              ansible.builtin.shell:
                cmd: "systemctl set-default graphical.target"
              changed_when: false
        ```
        
    - (확인) `ans all -m shell -a 'systemctl get-default'`


- 취약점 검사하기 - server_script.yml
    
    - 주요정보통신기반시설 기술적 취약점 분석 평가를 위해 다음과 같은 보안 취약점 검사 스크립트를 실행하고 결과 레포트를 수집한다.
    
      - 2022_ICTIS_Unix_v1.0.sh 파일을 root 권한으로 실행한다.
      - 스크립트를 수행한 결과 레포트를 제어노드의 ~/project/results2 디렉토리에 다음과 같은 이름으로 결과 파일을 수집한다.
        
      ```
        ~/project
          +-- results2
               +-- lb.example.com.txt
               +-- waf.example.com.txt
               +-- web1.example.com.txt
               +-- web2.example.com.txt
      ```        
    
  - (기술 취약점 분석 스크립트) 2022_ICTIS_Unix_v1.0.sh
  - chmod 777 2022_ICTIS_Unix_v1.0.sh
  - (플레이북) vi server_script.yml

    ```yaml
    ---
    - name: Server script
      become: true
      become_user: root
      hosts: all
      tasks:
        - name: Run script 2022_ICTIS_Unix_v1.0.sh
      ansible.builtin.script: 2022_ICTIS_Unix_v1.0.sh
          args:
            creates: 2022_ICTIS_Unix_v1.0.sh

    - name: Fetch the report file to control node
      ansible.builtin.fetch:
        src: "/root/Linux_server_script_result.txt"
        dest: "results2/{{ ansible_fqdn }}.txt"
        flat: true
    ```
  - (실행 스크립트) vi server_check_cronjob.sh

    ```bash
    #!/bin/bash
    
    echo "============================ 서버 취약점 검사를 시작합니다. ============================"
    cd /home/ansible/project
    ansible-navigator run -m stdout server_script.yml
    
    if [ $? -eq 0 ] ; then
        echo "[  OK  ] 서버 취약점 검사가 완료되었습니다."
        tree /home/ansible/project/results2
    fi
    ```
  - chmod +x server_check_cronjob.sh
  - ./server_check_cronjob.sh
  - (control 노드에 cronjob 등록) `crontab -e `
    ```bash
    # 분기마다 1일 00:05에 서버 취약점 검사
    5 0 1 3,6,9,12 * /home/ansible/project/server_check_cronjob.sh
    ```
  - (확인) cat results2/lb.example.txt

- 패키지 설치 - packages.yml
    
  다음과 같이 /home/ansible/project/packages.yml 이라는 플레이북을 생성한다.

  - web 호스트 그룹의 호스트에 Development Tools 그룹 패키지 그룹을 설치한다.
  - web 호스트 그룹의 호스트에서 iotop 패키지를 설치한다.
  - web 호스트 그룹의 모든 패키지를 최신 버전으로 한다.

  - (플레이북) vi packages.yml

    ```yaml
    ---
    - name: Install group packages
	hosts: web
	tasks:
		- name: Install Development Tools group, iotop packages
			ansible.builtin.dnf:
				name:
					- "@Development Tools"
					- iotop
				state: present  # latest
			
		- name: Update all packages
	    ansible.builtin.yum:
	      name: '*'
	      state: latest
    ```
    - (확인) `ans all -m shell -a 'rpm -q gcc iotop'`

- 컨테이너 환경 구성 - Ansible Galaxy를 사용하여 역할 설치
    
  /home/ansible/project/roles/requirements.yml 이라는 요구 사항 파일을 수정한다. 이 파일에는 Ansible Galaxy를 사용하여 역할을 다운로드하고 /home/ansible/project/roles 디렉토리 하위에 설치한다.

  - https://galaxy.ansible.com 사이트를 사용하여 docker 역할을 설치한다.
이 역할의 이름은 docker이다.

  - (플레이북) vi roles/requirements.yml

    ```yaml
    ---
    - name: balancer
      src: https://github.com/geerlingguy/ansible-role-haproxy/archive/1.3.1.tar.gz
    
    - name: phpinfo
      src: https://github.com/buluma/ansible-role-php.git
      
    - name: docker
    	src: https://galaxy.ansible.com/download/community-docker-3.1.0.tar.gz
    ```
    - (실행) `anx install -r roles/requirements.yml -p roles`

- 논리 볼륨 생성 및 사용
    
  web 그룹 관리형 노드에서 실행되는 /home/ansible/project/lv.yml라는 플레이북을 생성한다. 아래 요구 사항으로 논리 볼륨을 생성한다.

  - 논리 볼륨은 research 볼륨 그룹에 생성
  - 논리 볼륨 이름은 data
  - 논리 볼륨의 크기는 500 Mib
  - ext4 파일시스템으로 논리 볼륨을 포맷
  - 논리 볼륨을 /mnt/research 마운트. 반드시 부팅시에도 마운트 되어야 함.

  에러 처리 부분 추가

  - 생성된 파티션이 800Mib 크기 보다 작은 경우 'Size not Enough'라는 메시지를 표시
  - 노드에 sdb 장치가 없는 경우 'The device does not exist'라는 메시지를 표시

  - web1, web2에 1G짜리 하드디스크를 추가로 장착한다.
  - (확인) `ans web -m shell -a 'lsblk'`

    sdb가 루트 파일 시스템이 아닐 때까지 재부팅 후 작업 진행

    - (재부팅) ans web -m reboot 

  - (플레이북) vi lv.yml (모듈 사용)

    ```yaml
    ---
    - name: Disk partition operations
    	hosts: web
	  tasks:
    		- name: Check existing sdb
    			ansible.builtin.fail:
    				msg: "The device does not exist"
    			when: ansible_devices['sdb'] is not defined
		
    		- name: parted task
    			community.general.parted:
    				device: /dev/sdb
    				number: 1
    				part_start: 1MiB
    				part_end: 100%
    				flags: [ lvm ]
    				state: present
		
    		- name: Gather facts
    			ansible.builtin.setup:
    				filter:
    					- 'ansible_devices'
		
    		- name: Check partition size
    			ansible.builtin.fail:
    				msg: "Size not Enough"
    			vars:
    				sdb1_size: "{{ (ansible_devices['sdb']['partitions']['sdb1']['size'] | split)[0] }}"
    			when: (sdb1_size | float) < 800
		
    		- name: Create vg
    			community.general.lvg:
    				vg: research
    				pvs: /dev/sdb1
		
    		- name: Create lv
    			community.general.lvol:
    				vg: research
    				lv: data
    				size: 500m
		
    		- name: Make filesystem
    			community.general.filesystem:
    				fstype: ext4
    				dev: /dev/research/data
    				force: true
				
    		- name: Mount task
    			ansible.posix.mount:
    				src: /dev/research/data
    				path: /mnt/research
    				fstype: ext4
    				opts: defaults
    				state: mounted
    ```
    - (실행) `ann lv.yml`

   - (Ad-hoc) 기존에 생성된 파티션을 삭제
      ```bash
      ans web -m shell -a 'sudo umount /mnt/research && sudo lvremove -f /dev/research/data && sudo vgremove -f /dev/research && sudo pvremove -f /dev/sdb1 && sudo wipefs -a /dev/sdb && sudo parted /dev/sdb rm 1'
      ```
      - (확인) `ans web -m shell -a 'lsblk'`

  - (플레이북) vi lv2.yml (collection role 사용)

    ```yaml
    ---
    - name: Disk partition operations
    	hosts: web
    	tasks:
    		- name: Check existing sdb
    			ansible.builtin.fail:
    				msg: "The device does not exist"
    			when: ansible_devices['sdb'] is not defined
		
    		- name: Using     fedora.linux_system_roles.storage role
    			ansible.builtin.include_role:
    				name: fedora.linux_system_roles.storage
    			vars:
    				storage_pools:
    					- name: research
    						type: lvm
    						disks:
    							- /dev/sdb
    						volumes:
    							- name: data
    								size: 500m
    								mount_point: /mnt/research
    								fs_type: ext4
    								state: present
    ```
    - (실행) `ann lv2.yml`
    - (확인) `ans web -m shell -a 'lsblk'`

  [조건 변경] 모든 관리노드에서 실행되는 /home/ansible/project/lv3.yml 이라는 플레이북을 만든다.

  - 다음 요구 사항을 갖춘 논리 볼륨을 만듭니다.
    - 논리 볼륨은 research 볼륨 그룹에 생성, 논리 볼륨 이름은 data
    - 논리 볼륨 크기는 1500 MiB
    - xfs 파일 시스템으로 논리 볼륨을 포맷
    - 노드에 sdb 장치가 없는 경우 'The device does not exist'라는 메시지를 표시
    - 요청한 논리 볼륨 크기를 만들 수 없는 경우 오류 메세지
    Could not create logical volume of that size 표시되며 크기 800 MiB가 대신 설정됨
    - 볼륨 그룹 research가 없는 경우 오류 메세지
    Volume group does not exist 표시
    - 논리 볼륨을 마운트 하지 않음

  - (확인) `ans web -m shell -a 'lsblk'`
sdb가 루트 파일 시스템이 아닐 때까지 재부팅 후 작업 진행
    - (재부팅) `ans web -m reboot`
  - (web 그룹) 기존에 생성된 파티션을 삭제
    ```bash
    ans web -m shell -a 'sudo umount /mnt/research && sudo lvremove -f /dev/research/data && sudo vgremove -f /dev/research && sudo pvremove -f /dev/sdb1 && sudo wipefs -a /dev/sdb && sudo parted /dev/sdb rm 1'
    ```
    - (확인) `ans web -m shell -a 'lsblk'`
  - (플레이북) vi lv3.yml

    ```yaml
    ---
    - name: Disk partition operation
      hosts: all
      tasks:
        - name: Check existing sdb
          ansible.builtin.fail:
            msg: "The device does not exist"
          when: ansible_devices.sdb is not defined

        - name: Parted tasks
          community.general.parted:
            device: /dev/sdb
            number: 1
            part_start: 1MiB
            part_end: 100%
            flags: [ lvm ]
            state: present

        - name: Create vg
          community.general.lvg:
            vg: research
            pvs: /dev/sdb1
            state: present

        - name: Gather fact
          ansible.builtin.setup:
            filter:
              - 'ansible_devices'
              - 'ansible_lvm'

        - name: Check existing research vg
          ansible.builtin.fail:
            msg: "Volume group does not exist"
          when: ansible_lvm.vgs.research is not defined

        - name: Block ~ rescue
          block:
            - name: Check volume size
              ansible.builtin.fail:
                msg: "Could not create logical volume of that size"
              vars:
                sdb1_size: "{{ (ansible_devices.sdb.partitions.sdb1.size | split)[0] }}"
              when: (sdb1_size | float) < 1500

            - name: Create lv
              community.general.lvol:
                vg: research
                lv: data
                size: 1500m

            - name: Make filesystem
              community.general.filesystem:
                fstype: xfs
                dev: /dev/research/data

          rescue:
            - name: Create lv
              community.general.lvol:
                vg: research
                lv: data
                size: 800m

            - name: Make filesystem
              community.general.filesystem:
                fstype: xfs
                dev: /dev/research/data
    ```
    - (실행) `ann lv3.yml`
    - (확인) `ans web -m shell -a 'lsblk'`

- FTP 서버 구성
    
  FTP 서버를 구성하는 /home/ansible/project/ftp.yml 파일을 생성한다.
  - 플레이북으로 FTP 서버 구성 시 조건은 다음과 같다.
    - web2 관리 노드에서만 실행된다.
    - Anonymous FTP 서비스는 비활성화 한다.
    - vsftpd 패키지를 사용하여 설치하고, 서비스는 부팅 시도 기동 된다.
    - root 사용자는 원격에서 접근이 가능해야 한다.
    - 방화벽에 포트가 영구적으로 등록되어 있어야 한다.
  - (플레이북) vi ftp.yml

    ```yaml
    ---
    - name: FTP server setting
    	hosts: web2.example.com
    	tasks:
    		- name: Install packages
    			ansible.builtin.dnf:
    				name:
    					- vsftpd
    					- ftp
    					- firewalld
    				state: present
		
    		- name: Start and enable service
    			ansible.builtin.systemd:
    				name: "{{ item }}"
    				state: started
    				enabled: true
    			loop:
    				- vsftpd
    				- firewalld
		
    		- name: Configure anonymous disabled
    			ansible.builtin.lineinfile:
    				path: /etc/vsftpd/vsftpd.conf
    				regexp: '^anonymous_enable='
    				line: "anonymous_enable=NO"
    			notify: restart_vsftpd
			
    		- name: Configure allow root
    			ansible.builtin.lineinfile:
    				path: "{{ item }}"
    				regexp: '^root'
    				line: '#root'
    			loop:
    				- /etc/vsftpd/ftpusers
    				- /etc/vsftpd/user_list
		
    		- name: Firewall port open
    			ansible.posix.firewalld:
    				service: ftp
    				permanent: true
    				immediate: true
    				state: enabled

    	handlers:
    		- name: restart_vsftpd
    			ansible.builtin.systemd:
    				name: vsftpd
    				state: restarted
    ```
    - (실행) `ann ftp.yml`
    - (확인) `ftp web2`
      - root 사용자로 로그인 후 확인
      - anonymous 사용자로 로그인 실패 확인

- MAIL 서버 구성
    
  CentOS 9에서 메일 서버를 설정하는 /home/ansible/mailserver.yml 플레이북을 작성한다.

  - web2 관리노드를 mail 서버로 사용한다.
  - Postfix와 Dovecot을 설치하고 설정하며, 서비스가 시작되고, 부팅 시 자동으로 시작되도록 설정한다.

  - (수정)  vi inventory
    ```yaml
    [waf]
    waf.example.com ansible_ssh_host=192.168.1.110

    [lb]
    lb.example.com ansible_ssh_host=192.168.1.200

    [web]
    web1.example.com ansible_ssh_host=192.168.1.104
    web2.example.com ansible_ssh_host=192.168.1.105

    [mail]
    web2.example.com
    ```

  - (플레이북) vi mailserver.yml
    ```yaml
    ---
    - name: MAIL server setting
      hosts: mail
      tasks:
        - name: 시스템 패키지 업데이트
          ansible.builtin.dnf:
            name: "*"
            state: latest

        - name: Postfix 설치
          ansible.builtin.dnf:
            name: postfix
            state: present

        - name: Dovecot 설치
          ansible.builtin.dnf:
            name:
              - dovecot
              - dovecot-mysql
              - dovecot-pigeonhole
            state: present

        - name: Postfix 메일 서버 설정
          ansible.builtin.template:
            src: postfix_main.cf.j2
            dest: /etc/postfix/main.cf
          notify:
            - Restart postfix

        - name: Dovecot 설정
          ansible.builtin.template:
          src: dovecot.conf.j2
            dest: /etc/dovecot/dovecot.conf
          notify:
            - Restart dovecot

        - name: Postfix를 시작하고 부팅 시 자동 시작 설정
          ansible.builtin.systemd:
            name: postfix
            state: started
            enabled: true

        - name: Dovecot을 시작하고 부팅 시 자동 시작 설정
          ansible.builtin.systemd:
            name: dovecot
            state: started
            enabled: true

      handlers:
        - name: Restart postfix
          ansible.builtin.systemd:
            name: postfix
            state: restarted

        - name: Restart dovecot
          ansible.builtin.systemd:
            name: dovecot
            state: restarted
    ```
  - (Postfix 설정 템플릿) vi postfix_main.cf.j2
    ```
    # /etc/postfix/main.cf
    myhostname = {{ ansible_hostname }}
    mydomain = example.com
    mydestination = $myhostname,   localhost.$mydomain, localhost, $mydomain
    inet_interfaces = all
    inet_protocols = ipv4
    home_mailbox = Maildir/
    smtpd_tls_cert_file = /etc/ssl/certs/mail.crt
    smtpd_tls_key_file = /etc/ssl/private/mail.key
    smtpd_use_tls = yes
    smtp_tls_security_level = may
    smtpd_tls_security_level = may
    smtpd_tls_loglevel = 1
    ```
  - (Dovecot 설정 템플릿) vi dovecot.conf.j2
    ```
    # /etc/dovecot/dovecot.conf
    disable_plaintext_auth = no
    mail_location = maildir:~/Maildir
    service imap-login {
      inet_listener imap {
        port = 0
      }
      inet_listener imaps {
        port = 993
        ssl = yes
      }
    }
    ssl_cert = </etc/ssl/certs/mail.crt
    ssl_key = </etc/ssl/private/mail.key
    ```
  - 사용자 정의 변수 파일
    - 메일 서버의 호스트 이름과 도메인에 대한 정보 설정
    - vi vars.yml
      ```yaml
      ---
      ansible_hostname: web2.example.com
      mail_domain: example.com
      ```
    - (실행) `ann mailserver.yml -e @vars.yml`
