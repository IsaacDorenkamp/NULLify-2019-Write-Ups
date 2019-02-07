NULLify 2019 Writeups
=====================

Web
=====================

## Web 100 - Robots

Clearly, this problem starts out as a run-of the mill "robots.txt" problem. First, we go see what robots.txt is hiding. The contents we find are:

`User-agent: *<br />Disallow: /cgi-bin/exploit`

So our flag is going to be somewhere in this "exploit" page. Visiting this page, we see something like the following:

`06:51:42 up 4 days, 51 min, 0 users, load average: 23.85, 22.71, 22.45`

To the observant user, this is the result of the `uptime` command in Linux. This problem involves the ShellShock exploit,
which can be used to coerce the server into executing arbitrary Linux commands and dumping the results to the webpage.

This is attained by sending custom headers in our request, which may look a little odd. But here's how it works:

`custom: () { :; }; echo; echo; /bin/sh -c '<command goes here>'`

The reason it works is because the server program uses bash to process the headers, presumably by setting them
as environment variables. When someone sends a header like this, it defines the header as a function and proceeds
to execute any commands following the function definition. We must use "echo" twice in order to create a proper space
between the response headers and the content, otherwise the server catches on that something is wrong and sends a
500 Internal Server Error page. However, when using echo twice, no such error occurs because after echoing two blank
lines, the server is no longer processing headers and won't break if it encounters "bad data" which it interprets as
"bad headers". Back, to it, let's do some exploiting. I use Postman to send custom requests, but this is also possible
in BurpSuite or by manually typing out an HTTP request in PuTTY. We send the header template shown above, and for our
command we insert `ls`. We obtain the following response:

`exploit`

Hmmm, no luck. Let's try looking at things top down: this time, make the command `ls /`. As a result, we obtain

`bin<br />boot<br />dev<br />etc<br />flag.txt<br />home<br />lib<br />lib64<br />media<br />mnt<br />opt<br />packages<br />proc<br />root<br />run<br />sbin<br />srv<br />sys<br />tmp<br />usr<br />var`

`flag.txt`! We are in business. The next part is trivial. Simply send the command `cat /flag.txt`.

The flag we get is `NULL{The_Th0u$@nd_y@rD_sT@r3}`.

## Web 200 - Hackerman

Accessing this page, we see a fairly minimal page with nothing but a couple of links. Trying the links, we are taken to the
URLs `http://challenge.nullify.uno:5252/index.php?page=submit` and `http://challenge.nullify.uno:5252/index.php?page=login`,
both pages of which are empty. The URL format seems possibly susceptible to any LFi directory transversal attack. We try
to access a common readable file by entering the URL `http://challenge.nullify.uno:5252/index.php?page=/etc/passwd`. Sure enough,
we get a dump of the file's contents:

`root:x:0:0:root:/root:/bin/bash daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin list:x:38:38:Mailing List
Manager:/var/list:/usr/sbin/nologin irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin systemd-timesync:x:100:103:systemd
Time Synchronization,,,:/run/systemd:/bin/false systemd-network:x:101:104:systemd Network
Management,,,:/run/systemd/netif:/bin/false systemd-resolve:x:102:105:systemd
Resolver,,,:/run/systemd/resolve:/bin/false systemd-bus-proxy:x:103:106:systemd Bus
Proxy,,,:/run/systemd:/bin/false
hackerman:x:1000:1000::/home/hackerman:/home/TlVMTHtUQGszX3MwbTNfRnIzM19wMDFudHp9Cg==`

Notice the suspicious base64 string in the bottom line. Let's decode that and see what
we get:

`NULL{T@k3_s0m3_Fr33_p01ntz}`

This is not our Hackerman flag; it is, however, the Hackerman Bonus Flag, worth 25 points.

Now that we have found a way to read files, perhaps our flag file is not too far away. We may
try `http://challenge.nullify.uno:5252/index.php?page=flag.txt`, but this is a false flag file
which contains no useful information. However, recalling the /etc/passwd file, we see that there
is a user called 'hackerman', and his home folder is /home/hackerman. Perhaps the flag is there
instead? Our attempt: `http://challenge.nullify.uno:5252/index.php?page=/home/hackerman/flag.txt`.

This time we get results. The flag obtained from this file is `NULL{LFI_FTW_and_Th3_lulz}`.

## Web 300 - PHP Host

Opening this webpage is extremely disappointing. There is nothing but text. However, this does expedite
our process of searching for a vulnerability. It seems clear now that it would be more beneficial to look
through our request and response headers. It is interesting, one may notice, that this webpage located at
challenge.nullify.uno:5353 calls itself hsctfwebhosting.com on its disappointingly plain page? Perhaps a
change of the Host header will make a difference. If we send a custom request with the Host header set to
`hsctfwebhosting.com`, we obtain something different:

`Welcome to HS CTF web hosting! This is our customer facing page. Please use us for all your web hosting needs!`

We are not simple customers, though! We want administrator access, if we can find it. It seems obvious now
that this problem is centered around the host header, so taking a bit of a shot in the dark, perhaps there is
an administrator subdomain? We try setting the host to admin.hsctfwebhosting.com. Bingo! Now we get a login form
of sorts - a simple username and password box. The page says 'Welcome to the admin panel! Here you can do admin stuff.'
Perhaps the username we seek is simply admin? We don't have much to go on as far as passwords go, and it never
hurts to take a shot in the dark again, and hope the password is simply the same as the username. We send a POST
request to this location (with the Host headers still set as we have them) with the POST form data indicating
a username 'admin' with a password which is also 'admin'. Our assumption worked! We get an admin page with the flag.
The flag is `NULL{s0m3th1ng_ab0ut_d1r3ct0r13s}`.

## Web 400 - Elite Hackerman

Going to this page is not nearly as disappointing as before. Someone actually wrote some CSS for this one! We see two
simple links, and they take us to the URLs `http://challenge.nullify.uno:5454/index.php?file=dashboard.html` and
`http://challenge.nullify.uno:5454/index.php?file=about.html` respectively. Perhaps we can get some insight on the contents
of index.php this way? We try this: `http://challenge.nullify.uno:5454/index.php?file=index.php` but no luck:

'php extensions are blocked!'

Assuming this is some kind of filter, we can make some guesses about the weakness of such a filter. One common assumption
about file extensions is that they are always lowercase. Wrong. So we might try `http://challenge.nullify.uno:5454/index.php?file=index.PHP`,
being certain to put the extension in capital letters. As a result, we see a page with some rogue PHP! If we view the page's source, we will
get a better insight into the code. In fact, there is a list of files in the directory! This includes one we did not previously know about,
testdashboard.php. We proceed to check the contents of testdashboard.php using the same method used on index.php. The code is simple - checking
for a password hidden in the secret password.txt file. If an incorrect password is provided, it leaks the password file, but we do not need
this particular leak in order to view the password. The mechanism in index.php to prevent directory transversal is broken - if we separate the
'..' and the '/' by '../', then the filter will remove the '../' between the two and leave behind a '../', allowing us to travel across directories
by using '....//' instead of '../'. We then try `http://challenge.nullify.uno:5454/index.php?file=....//secret/password.txt` and obtain the password:

`83218ac34c1834c26781fe4bde918ee4`

Now, we attempt to access testdashboard.php: `http://challenge.nullify.uno:5454/testdashboard.php?password=83218ac34c1834c26781fe4bde918ee4&directory=/`.
We get a directory listing of the top-level directory which includes a unique folder: t3stda5hb0ard. The directory listing of this folder includes a
single file: `flag.txt`. Using our method of directory transversal again, we try the URL
`http://challenge.nullify.uno:5454/index.php?file=....//....//....//t3stda5hb0ard/flag.txt` and get our flag, `NULL{s0m3th1ng_ab0ut_d1r3ct0r13s}`, which
is oddly the same flag as Web 300. Likely a human error on their end.

## Web 500 - Alien Guidance

Opening this webpage, we see an eyesore of a login page. There is a forgot password field, so one might reasonably think this could serve a useful
purpose for our hacking journey. Entering various phony usernames, we see messages like `If your user account exists (asdf) we've sent you a password reset.`
We are given the knowledge that this site uses twig, a templating service. Also, in the "news" section below the form, there is information about an api
which requires an API Key called 'globalAPIKey'. Perhaps we may inject a template into the webpage. Maybe entering '{{ globalAPIKey }}' into the system will
read the key into the templated message? Attempting this, we get the message
`If your user account exists (abcdcbacsbabacbacbdacbacbacbacbacbbcd) we've sent you a password reset.`

Bingo. We have our API Key. Now, we try to access this famed API. We try `challenge.nullify.uno:5555/api` and see that the API Key should be entered in the
GET parameter 'apikey'. So we add the parameter apikey with the value of our newly found API key. Now, we get a message saying that we need a 'method' parameter.
We have no insight to what methods are accepted, so let's just enter a random value and see what the site might leak to us. Trying that, we get a message telling
us that 'user' is the only accepted method. Trying a URL with the method set to 'user', we get a message telling us that we are missing the 'id' parameter. It
is reasonable to believe that this is a user id, taking the form of an integer. One might try a user id of 0, but this leads to an error saying no such user
exists, so we try 1 instead. This gives us the leak of a lifetime:

`{"username":"admin","password":"YjA5MGZhZTQ3MWE3MjliOGRhNmVkYTViYjUwMzc4OTBkZWI3OGE0NDk0NDNmYTg2YTQ5ZmJkNGYzYWNmZmJhZGQyOGEzMzJlYzg1YjU3MWZiZmJlMDc4ZGI5OTBhNDU5YzVmOThiNjFkNGUxZmEyOGU0NDg3Yjg2MWFjOGNhOGQ="}`

Decoding the password from base64, we get `b090fae471a729b8da6eda5bb5037890deb78a449443fa86a49fbd4f3acffbadd28a332ec85b571fbfbe078db990a459c5f98b61d4e1fa28e4487b861ac8ca8d`.
One might guess that this is the password, but if this username/password combination is attempted, it fails. So, the next reasonble idea is that this is a
hash of a password. In fact, it is a hash that can be cracked by an online tool, simply found by looking up "hash cracker". I used crackstation.net, there
are probably a myriad of other sites that work. The hash cracker tells us that this hash is the SHA-512 hash of the word "coffee". Wow. Trying this
username/password combination does it - we're in.

The page is disappointing, however. Nothing but text and two non-functioning buttons. Taking a look at the source, however, we discover an attached Javascript file.
The file's name is not particularly revealing, but taking a look at the source, we see that it is a tool for implementing code editors into webpages. However, there
is a function at the top which, perhaps at first glance blends in, but truly doesn't belong once you notice that it sends an AJAX request to the NULLify server with
the "POST" method and a property called 'ip'. However, the function should be re-defined in the DevTools console so it does not attempt to send the request twice
and trigger an error. Calling the function with any plain text reveals that the service returns the same webpage, but with the text appended to the top. However,
in a hacker's mind, there is a belief that this text may be echoed through some call to a shell. If this is the case, all we need to do is start our text with a
semi-colon and enter what command we desire. This is attainable. By sending a request with the ip ';ls', we get a listing of the files in the directory as desired.
There is a single text file in the directory, which is indeed curious. Accessing this file in the browser gives us the long-desired (and humorous) flag:
`NULL{y0u_c0u1dv3_gu3ss3d_coffee}`! However, it also indicates that there is a bonus flag, and we have to 'go higher' to get it.

This could mean 'higher' in the directory tree, or 'higher' in user privilege - possibly both. We can continue using our method of sending requests to find out.
Sending ';ls /' shows a file called 'root.txt' is present, which is suspicious. However, you will have no luck getting its contents - by examining the root
directory with ';ls -l /', we see that we need root privileges. One effective way to gain root privileges temporarily is through an SUID program - a program
allowed to temporarily elevate the user's privilege to execute certain tasks. We can actually search for SUID programs, thanks to the Linux command `find`.
In particular, we send a request with the ip value set to `;find / -perm -u=s -type f` and this will search the system for SUID programs. We get a nice list after
this request - which, be aware, takes a little while to complete, so be patient. There is one file in this list which sticks out like a sore thumb, however:
`/bin/readfile`. We pounce on this, and try a request with the ip value set to `;/bin/readfile /root.txt`, and just like that, we have the last of all the Web flags:
`NULL{su1d_0_hAcc_her0}`.

PWN
=====================

## PWN 100 - Easy Intro
This problem is an extremely quick and easy solve. Upon running the executable, it only demands we overflow the buffer. This is easily achieved. The flag is
`NULL{6dcda80356a36ec26b38253a373d64a177b98b428b18d857cd4144308340ba4f}`.

(More to come! I have completed several other PWN problems, the Script problems, all Crypto problems up to 400 so far.)
