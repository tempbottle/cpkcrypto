# Introduction #

Here we list some frontends of the CPK crypto library:

### Key management server ###

Key management serveris a web server based on PHP, Apache
and some CGI binaries which is used for CPK system setup, key
extractions and user/identity management and write the generated
private key into USB tokens. This system is developed in Peking Univ.
from 2004 to 2005, the new version is maintained by e-Henxen Co, Ltd.

### Microsoft Outlook plug-in ###
Microsoft Outlook plug-in can automatically do CPK signing,
verification, encryption and decryption of email messages in and out of
the most popular email client -- Outlook. This plug-in is the most
important demonstration application of CPK that developed by
Wenjia Guo (\email{guowj@infosec.pku.edu.cn}) in 2005 and has not been
maintained any more.

### Gnome GUI scripts ###

Gnome GUI scripts apply \texttt{zenity}
(\url{http://live.gnome.org/Zenity})
to provide some simple dialogs in Gnome for CPK system setup, key extraction,
file signing and encryption. These scripts are the frontends of the CPK
command line toolkit that add a mouse right click menu item
to the nautilus filesystem browser which makes the signing and encryption of
multiple files very easy. For the desktop environment in OpenSolaris is also
include Gnome, these scripts can be ported to OpenSolaris.


### Digital seal ###

Digital Seal is a GUI system that provides graphical digital
signatures. In the tradition of China, the seal is seen as the credentials
instead of the handwriting signatures in the west. Even in today, the round red
seal is used to authenticate the government paper documents. This system include
a shell script based on **ImageMagick** (http://www.imagemagick.org/) command
line tool that extact the identity information from a
> Ver 0.6 CPK signature and transform it into a seal picture. The original shell
> version of this program is designed by the author and developed by Wenjia Guo,
> that the seal picture is automated generated from the signature without maintain
> a seal picture database or embedding the seal picture into the signature. A commercial
> > version is applied in China Minsheng Banking Co, Ltd. (http://www.cmbc.com.cn/)
> > which is also based on the CPK crypto library version 0.6 but the design of the
> > digital seal components maybe different from ours.