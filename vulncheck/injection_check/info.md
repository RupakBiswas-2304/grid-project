## Which files are used to store database configuration ?
- #### python
    - settings.py ( all data base configuration for django )
    - db.py (for raw connection )
    - model.py (used in django )
    - keyword to search 
        - cursor
        - 



# sql queries in python
Q = f"INSERT INTO `users` (`id`, `name`, `email`, `password`) VALUES (1, '{name}', '{email}', '{password}')"
Q2 = f"INSERT INTO `users` (`id`, `name`, `email`, `password`) VALUES (1, '{name}', '{email}', '{password}')"
Q3 = f"SELECT * FROM `users` WHERE `name` = '{name}'"
Q4 = f"SELECT users.id, users.name, users.email, users.password FROM users WHERE users.name = '{name}'"
Q5 = "select * from users where name = %s" % name"
Q7 = "delete from users where name = %s".format(name)"
Q8 = "select `id` from `session` where `session_id` = %s" % session_id
Q9 = "select * from `session` where `session_id` = %s" % session_id"
Q1 = "select auth_user.id, auth_user.name, auth_user.email, auth_user.password from auth_user where auth_user.name = %s" % name
Q11 = "select id from auth_user where name = %s and email = %s and password = %s" % (name, email, password)

