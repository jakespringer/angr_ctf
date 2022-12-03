Eventually, this README will have complete and more detailed information about building, installing, and playing the levels.

Currently, if you want to play around with them, take a look at `package.py`, which builds the levels, and `dist/` which generally has an up-to-date build of each of the levels.

A Makefile is included that performs an automated build for both a local installation and for the MetaCTF web installation.
  A list of users is passed in via the `USERS` environment variable, which will then build the binaries for each user listed.

## Building
### Local
Build binaries in `obj/{foo,bar}/angr`: <br>
  ```make USERS='foo bar' local```

* You can go to the target directory (`obj/{foo,bar}/angr`), you'll find the built binaries as well as the python files to play the levels

### Web, MetaCTF
Build binaries in upper-level MetaCTF repo `../www/static/obj/{foo,bar}/angr`: <br>
  ```make USERS='foo bar' web```

## Playing the levels
Eventually, you'll find a walkthrough for playing some levels at [walkthrough](walkthrough/)

In the meantime, check these other interesting resources: 
* https://blog.notso.pro/2019-03-20-angr-introduction-part0/
* https://github.com/ZERO-A-ONE/AngrCTF_FITM from [@ZERO-A-ONE](https://github.com/ZERO-A-ONE)

## Troubleshooting
While compiling using "`make USERS=<user> local`" you might have the following error: <br>
`fatal error: bits/libc-header-start.h: No such file or directory`

One easy fix is to install the missing headers and libraries using: <br>
  ```sudo apt-get install gcc-multilib```
