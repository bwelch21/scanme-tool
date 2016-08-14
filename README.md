Scanme Tool Documentation

Overview

This site was built to be a portal for performing some basic management tasks for lab devices. Its current functions are: update, add, or delete a device from the site's database of network devices, retrieve diagnostics and statistics for specific devices, update user passwords for specific devices, and perform Nmap scans of devices or subnets. When a user visits the site, they will be presented with the four options, and will be redirected according to whichever one they choose. The current operating systems supported by this site are Junos OS, Cisco IOS, Cisco IOS XE, Cisco IOS XR, and Cisco NX.

Manage Devices Function

The Manage Devices page consists of three tabs: "Add a network device", "Update/Delete a network device", and "List network devices". The function of each is as their names suggest. The network devices are listed in the order in which they are added. Each device in the database is given an ID which acts as a way for the database to identify each record. This value is created by the database and cannot be edited by the user; however, it can be seen by the user since it is necessary for selecting a device to be edited or deleted. When a user chooses to add a network device, they are presented with a form in which they must input some basic information about the device they would like to add. After submitting this form, the newly added device can be found at the end of the list of network devices.

This list of network devices must be updated as the devices that you want to be managed by this site changes and as specific device information changes (e.g. if the devices IP address changes, then the IP in the database will no longer be accurate unless it is manually changed). It is important to keep this list updated to ensure accurate information from certain functions. For example, it is possible to gain statistics on every device in the network devices database at one time. If a device changes IP address and the database isn't updated accordingly, the output given for specific IP address could be non-existent or, if the old IP address is now being used by another device, will be incorrect.

Health Check
The Health Check option provides a way to test a device's connectivity and gain valuable statistics about the device at the same time. When the page is visited, the user is presented with a form that takes the IP address of the device (if "All Devices" is not selected) and its operating system. If "All Devices" is selected, then every device in the site's network devices database will be checked and the input into the other fields is not used. When a "health check" is run, the web server attempts to connect to the specified IP via SSH. If a connection is successfully established, the show version command will be run on the device. The output will be parsed, and returned to the user in a readable format. The "All Devices" option will do this for every device in the database. This will, by nature, take a significant amount of time to complete.

Password Updater

The Password Updater option allows the easy management of user account passwords on any of the previously mentioned supported operating systems. This application requires that the user input the IP address of the device, the username of the account whose password will be changed, the new password, and the device's operating system. When executed, the web server will attempt to establish an SSH connection with the device, and the go on to update the password as specified.

Nmap Scanning Application

The application provides a user interface to the well-known, command-line troubleshooting tool Nmap. Within the Scanme Tool, the NSA provides another, more customizable way to test a device's connectivity than the Health Check option. The feedback of the two programs is also different.

How to Admin the Scanme Tool

The server that the Scanme Tool runs on is an Ubuntu 14.04 Virtual Machine. Web2py and all of its corresponding files are stored in the opt/scanme/ directory. The Scanme Tool (its application name is Nmap within web2py) uses multiple Python and Expect scripts to carry out its function on remote devices. These scripts can be found within the opt/scanme/python-scripts/ directory. To be used in connecting remote hosts, configuration files are stored in the etc/ directory.

Launching Web2py

To launch web2py, log in as root and run the commands:
cd /opt/scanme
python web2py.py -k myapp.key -c myapp.crt -i 127.0.0.1 -p 8000

This method of starting the web2py will close it as the SSH session closes. Information on starting a process independent of the SSH session can be found here: http://askubuntu.com/questions/8653/how-to-keep-processes-running-after-ending-ssh-session
The "-k myapp.key -c myapp.crt" part of the command makes the site run over https and tells web2py to use the self-signed certificate that is stored on the server. After running the command, you will be prompted to enter a database password; this password will be required for anyone trying to log in to web2py's administrative interface. Once you enter the password, the site should be up and running and ready to be used.

The Web2py Framework

As mentioned before, web2py is a Python based, full stack web development framework that allows for the easy creation and maintenance of web applications. Web2py separates the development process into three main categories: Models, Views, and Controllers. Models files contain the different databases that application uses. Web2py separates the data representation (the model) from the data presentation (the view) and also from the application logic and workflow (the controller). Web2py provides libraries to help the developer design, implement, and test each of these three parts separately, and makes them work together. For further reading and as a reference, see the web2py documentation.

Admin Interface

The web2py administrative interface provides an all-in-one portal for managing any installed applications on the site. It is accessible by visiting the URL https:// 127.0.0.1:8000/admin. This page will prompt you to enter the "Administrator Password". This is the password that was chosen after running the command to launch web2py from the server. Enter the password.
The next page you will see lists all of the installed applications on the site and some forms for creating or uploading an application to the site. On the right side of the page, you will see the version of web2py and Python being used. Web2py runs on Python 2.7 so don't update it to Python 3. If an update is available for the web2py framework, a button/link will be displayed that says "Update the web2py framework". Click this button, confirm, and then wait; that's it. There should be three applications listed: examples, nmap, and welcome. Examples and welcome come by default when web2py is initially downloaded, however, the only application that is enabled is nmap. Clicking the drop-down list labeled "Manage" will display a list of options for that particular application. To edit any of the files associated with the nmap application, click "Manage", then "Edit".

Models

The Models section of the web2py administrative interface contains Python files in which the databases that the application uses are defined. The Scanme Tool only uses one user-defined database which is the network devices database. It is defined within the "db.py" file.
There is also a "database administration" button in this section. This will redirect you to a page that shows all of the available databases and tables for the application. All but the last of the databases listed are created by default by web2py. Selecting "db.network_devices" will bring up an administrative view of network devices database. From here, you can make any updates, deletions, or insertions that you want. This page also provides you with the option to import a CSV file to the database or to export the current database as a CSV. The CSV to be imported must have the same fields (except the ID field) as the database in the same order.

Controllers

The Controllers section contains all of the Python files where the application logic of the site is contained. If you're trying to find where a function of the site is carried out, it will almost always be in the controller. Specifically, the "default.py" file. Beside the filename, is a list of all of the pages that are defined within this file. Clicking the "Edit" button beside the "default.py" filename will display the files contents and allow you to make any changes that you want. More on this in the "Application Logic" section of the page.

Views

The Views section is contains the HTML files associated with each page defined by a function in the "default.py" controller file. Each View is associated with functioned defined in the default.py file must have a name that begins "default/" to tell which controller file to look for the page logic in. Its name must also be exactly the same as the default.py function you want associated with it.

Application Logic

The most complex portions of the sites application logic is within the Health Check option, the Password Updater, and the Nmap Scanning Application. Of these three, there are two categories: the logic of the function is carried out within the web2py controller, or the logic is mainly carried out within scripts stored locally on the web server. 
As was mentioned before, the Health Check and Password Updater both rely on Python and Expect scripts that have been stored in the /opt/scanme/python-scripts directory in order to carry out their function.

How the Health Check Works

The Health Check logic is held in the login_show( ) function in the default controller and its associated view is default/login_show.html. When the user visits the Health Check page, they are shown a "Test Device Connectivity" form that asks for the IP address of the device to be checked and its operating system. If the user does not know the devices OS, there is an option for that as well. In addition to these, there is an "All Devices" option that, when checked, will check all the devices in the network devices database. The output of this application is the result of running a "show version" on the given device. To accomplish this, the application must be able to:
1.	Log in to the specified remote device via SSH 
2.	Run the show version command and catch its output 
3.	Close the SSH connection 
4.	Parse the output of the "show version" command and return it to the user

Steps 1-3 are all carried out by a Python script named "show_version.py". Once the "Test Device Connectivity" form is submitted, some input validation is performed on the IP address entered (determining if it is a valid address and not words), if it passes, the function uses the a spawns a subprocess (using the Python subprocess module) and prepares waits to catch the output of the call. The subprocess that is created is the the running of the show_version.py scripts with the user input passed as command-line arguments. For example the line in the login_show() function
output = subprocess.check_output(["python", "/opt/scanme/python-scripts/show_version.py", show_host])
is equivalent to entering
$ python /opt/scanme/show_version.py show_host
at the terminal where "show_host" is the IP address of the remote device. The output of the script will then be stored in the "output" variable once it completes. When the scripts finishes, its output must be then be parsed so that the useful information can be returned. The output is parsed in the __parseOutput(oper, output) function in the controller. This function uses regex rules for finding output that are dependent on which OS the remote device is running. This function will return a dictionary of the statistics retrieved from each command and is eventually passed to the view once the page reloads in the line:
return dict(credentials=credentials, output=output, router_info=router_info, finished=finished, dev=__getDevicesInDB(), device_info_list=device_info_list, show_host=show_host, all_devices=allDev)
This brings up the important concept of passing variables to the views. For just about every page in this entire application, the controllers and associated views are required to share information. This is a one-way sharing, in that the controller decides what information it has that it wants the view to also be able to see and/or use. In the case of the login_show() page, the data being passed to the views is everything within dict( ) of the return statements. To pass data to the views, use this format. Dict() makes this data into a dictionary and everything on the left side of the = is what the variable will referred to as in the associated view. 

The login_show.html page must output the data in a way that the user can easily read. It uses HTML tables to do so. Because it cannot be known ahead of time how large the table will need to be, there is some page logic in Python loop through dictionary of output information, and build the table accordingly. Look in the login_show.html file for examples on entering Python code in the view files (no indentation is required; the "pass" keyword is used to indicate the end of a code block). If the scan was run on all the devices, the output is formatted the same way, but just with a table for every device. This completes Step 4 and highlights what happens when a Health Check is run on a device, or all devices.
*Note about the "All Devices" option: The nature of this option will take a large amount of time, and could use more testing/optimizing. Keeping this option enable is not recommended while the until it has been examined further.

How the Password Updater Works

Because of the interactive nature of changing passwords at a terminal, Python scripts were not suitable for the task. Instead, the password updater makes use of Expect scripts to update user passwords on Juniper and Cisco devices. Because the commands and interactive prompts are slightly different depending on the OS of the device being edited, so the there is a different script to perform a password change for ever different device supported by the site (Junos OS, Cisco IOS, IOS XE, IOS XR, and NX). These scripts can also be found in the /opt/scanme/python-scripts directory.
The Password Updater uses the same logic as the Health Check option and is, in a way, simpler to implement because the output does not need to be parsed. The steps involved once the password update form is submitted are as follows:
1.	Log in to the specified remote device via SSH
2.	Update the password for the specified user account using the commands specific to that OS
3.	Close the SSH connection
4.	Send the output to the user

As you can see, these steps are very similar to the steps of the Health Check. Again, steps 1-3 are handled by the scripts on the server. The Expect script is called in the exact same way as the Python scripts were in the Health Check and will update the password and return its output (essentially a command-line view of the command it ran) to the controller in web2py, where the script was called from.
Something to note about changing passwords on Cisco devices is that, by default, they only allow for TACACS login if it's enabled (which it will be for lab devices), so logging into the device via SSH as a local user will not work before or after you update the password.

How the Nmap Scanning Application Works

The application uses the network administration tool Nmap to carry out scans. The application provides a more convenient option than using Nmap from the command line (as it is primarily used). The coding logic behind the application is fairly simple to understand. The home page holds two separate forms, one basic scan options and the other advanced scan (hidden by default), and an option to display the advanced options. The user's input is taken in through the forms upon submitting, and is then processed by the program. During processing, input validation is performed on each text input and the command which will be used to execute the desired scan is built. Once the command is built, a 'subproccess' call to the terminal is made and the Nmap scan is started as a background process.
As the scan is carried out, the user is shown a screen informing them that the target(s) are being scanned and an option to abort the scan if necessary. It is easy to accidentally begin a scan that will take much longer than expected, so having the option to abort was important. Nmap does not have a built-in way to quit scans (Ctrl-C must be used from the command line), so devising a way to abort scans was challenging. Essentially, the program keeps track of each instance of the process (the scan) running and uses the subprocess module in Python to terminate that process when the user clicks the "abort" button on the loading screen.
Every 6 seconds, the loading page refreshes, each time querying the process as to whether or not it has completed. If not, the loading page is displayed again and the cycle continues. If it is finished, the user is redirected to the scan result page where the results of the scan are displayed. The results of the scan are written to a text file that is stored on the server. Each file is given a unique name based on the date and time the scan was started. The contents of that file are read by the program and are the results that the user is shown on the scan result page.
Issues, Bugs, and Future Work
Currently the Scanme Tool provides functionality for all of its functions and is effective in doing so. But there is always room for improvement / something that doesn't work quite right. Some known issues:
	The "All Devices" option for running in the Health Check option takes a very long time to complete and uses a lot of the system's resources while it is running. The way that function is carried out involves looping through all the devices in the database and running and calling the show_version.py script for each individual device. A Health Check on a single device takes ~6-10s to complete (to make the SSH connection, authenticate on the remote device, run the show version command, and parse a moderately sized output using regex), so >300 can take up to an hour. Perhaps using a single script that runs the show version on all of the devices in the database at once and takes a list of IPs as a command line argument would cut down on the time and system usage more (this script is already one the server as /opt/scanme/show_version_all.py). It's possible that with the current setup, others trying to use the application at the same time an all devices check is being run will experience a decline in site responsiveness.
	The output of all devices is not very pleasant to look at. It can be described as a table of tables.
	The network devices database does not have a field that represents the "Last Known Status" of the device (whether or not connectivity could be established).The idea for this would be that when a all devices check is ran, it would update this field for each particular device depending upon whether an error was encountered when trying to establish an SSH connection to that device.
	Ideally, the Password Updater script would be able to run on all devices in the database like the Health Check can. Along with adding this feature, explore other ways of passing arguments to the Expect script that will update the password.

