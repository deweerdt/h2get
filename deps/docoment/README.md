<p align="center">
  <img src="https://cdn.rawgit.com/reginaldl/docoment/master/logo.svg" alt="Docoment Logo" width="40%"/>
</p>

# Overview
Docoment extracts comments from C code and generates documentation.

# Requirements

Docoment requires python 2, and the following packages:

```
$ sudo pip install jinja2 clang
```

# How to use

- Create a docofile
```
[project]
name = project-name
path = <path>/src
       <path>/include
extra_args = -I <path>/include
files = *.c

[output]
json = true
html = true

[templates]
path = ./templates

```

- Run docoment
```
python docoment.py
```
