# windows_user_files

Populates the file system by adding the configured content to the specified user(s).
Note that file size limits may exist depending on your code hosting provider - Github limits at 100mb.

Usage:
- Add content that all users should have in their home directories to ./files/generic
- If you want only a specific user to have certain content, add that content to ./files/<username>

Variables used:
- working_dir

Potential extensions:
- add functionality to copy files to every user belonging to a certain group
- add equivalent role for linux