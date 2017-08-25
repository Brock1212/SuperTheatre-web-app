# SuperTheatre-web-app
A website that allows users to watch films online after paying for each.
The stripe Api is ueed in this application for accepting payments. In order to use it you must create a stripe account.
The database uses sqlalchemy. A nosql database.
To use this web app a user needs a settings.py file with the follwing

SQLALCHEMY_DATABASE_URI = 'sqlite:///data.db'
admin_password = 'who cares'
SECRET_KEY = '>5_m{<VzS]3@_h"Q.(N}U9+TqN[~8,{RNp-#bpc(XF#I^LovAXA*DsxES^X%L^N!E@9OWUiadb&d(*#-TnR6Y%62#(Ebg(xW'
st_secret_key = your stripe test secret key
st_publish_key = your stripe test public key

