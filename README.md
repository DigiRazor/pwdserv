# Go-PwdServ [![Build Status](https://travis-ci.org/DigiRazor/pwdserv.svg?branch=master)](https://travis-ci.org/DigiRazor/pwdserv)

Go-PwdServ is a lightweight password verification service for [Go](https://golang.org/).

This service supports the use of build-in validators, to validate a new password's complexity according to the rules enabled.

## Features

### Basic Rules

**Confirm Password:** Basic check to make sure that the new password and confirm password matches.

**Minimum Length:** Basic check for minimum length of the password.

**User ID/ User-name:** Basic check to not allow the user id/ user name be in the password.

**Upper-case characters:** Basic check to confirm if the password contains an upper-case character.

**Lower-case characters:** Basic check to confirm if the password contains a lower-case character.

**Numeric characters:** Basic check to confirm if the password contains a numeric character.

**Special characters:** Basic check to confirm if the password contains any of the supplied special character(s).

**White space:** Basic check to not allow white space in the password.

**Historical passwords:** Basic check to compare the password to any of the supplied historical password.

**Black-list:** Basic check to not allow the password to be any of the supplied password(s) in the list.

## Usage

This is a quick introduction (Go-PwdServ, world; world, Go-PwdServ):

