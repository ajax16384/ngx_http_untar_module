# Nginx HTTP Untar module
This [nginx](https://nginx.org/) module can serve static file content directly from tar archives.
Inspired by [nginx-unzip-module](https://github.com/youzee/nginx-unzip-module).

## Pre-built Packages (Ubuntu / Debian)

Pre-built packages for this module are freely available from the GetPageSpeed repository:

```bash
# Install the repository keyring
sudo install -d -m 0755 /etc/apt/keyrings
curl -fsSL https://extras.getpagespeed.com/deb-archive-keyring.gpg \
  | sudo tee /etc/apt/keyrings/getpagespeed.gpg >/dev/null

# Add the repository (Ubuntu example - replace 'ubuntu' and 'jammy' for your distro)
echo "deb [signed-by=/etc/apt/keyrings/getpagespeed.gpg] https://extras.getpagespeed.com/ubuntu jammy main" \
  | sudo tee /etc/apt/sources.list.d/getpagespeed-extras.list

# Install nginx and the module
sudo apt-get update
sudo apt-get install nginx nginx-module-untar
```

The module is automatically enabled after installation. Supported distributions include Debian 12/13 and Ubuntu 20.04/22.04/24.04 (both amd64 and arm64). See [the complete setup instructions](https://apt-nginx-extras.getpagespeed.com/apt-setup/).

## Features
* Zero-copy: outputs content directly from archive file (no temporary files)
* Caching parsed archive file entries: reduce archive scan-search time
* Supported tar item types: normal file, long file name data

## Configuration example
```nginx
  location ~ ^/(.+?\.tar)/(.*)$ {
      untar_archive "$document_root/$1";
      untar_file "$2";
      untar;
  }
```
## Module directives
***
**untar_archive** `string`

**context:** `http, server, location`

Specifies tar archive name.
***
**untar_file** `string`

**context:** `http, server, location`

Specifies file to be extracted from **untar_archive**.
***
**untar**

**context:** `location`

Invokes untar of **untar_file** from **untar_archive**
***
## Known limitations
* only GET,HEAD verbs supported
* no archive entries listing
* base tar format support (only normal files: no symlink, sparse e.t.c)

## TODO
* Limit cache archive descriptors, free expired archive descriptors
* GNU extension modification time format
