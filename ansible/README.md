# configure

create a `hosts` file in the `ansible` folder using the `hosts.example` file and change the public IP accordingly at the following line:
```
[all:vars]
ansible_ssh_common_args='-o ProxyCommand="ssh -o IdentitiesOnly=yes -A -p 22 -W %h:%p -q aecid@203.0.113.10"'
```
