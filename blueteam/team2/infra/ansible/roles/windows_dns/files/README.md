# files

This folder contains any and all files that this role may need to copy to the destination host.
Example: scored service content (website .html files), scripts, etc.
Your ansible tasks will refer to these files as "files/filename.txt".
One exception to the above: files using jinja2 variable substitution should be placed in the "templates" folder.