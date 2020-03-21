Simple PAM module to disallow password authentication
====

Based on [Writing Your First PAM Module](https://rkeene.org/projects/info/wiki/222).

```
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make 
```

Then, install the library in the appropriate location (`/lib/security`, `/lib/x86_64-linux-gnu/security`). 
Add the module to `/etc/pam.d/sshd`. 

```
# At the top of the file
# Check nopasswd file           
auth requisite pam_nopasswd.so
```
