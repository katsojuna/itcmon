The ITC Watch program displays wayside indications in a nicer format than ITCMON.

It gets its data from 'zjpub' servers, so you need to have either ITCMON or IGW running.

It will look for the rrdata.json file and the wius subdirectory in the connected directory the .exe is in.

In addition, if you add milepost numbers to your WIU data, then you can sort the output based on this, for example:


    "780207601703": {
      "name": "Oak Ave",
      "MP": 348,
      "sig": "UP",
      ...
      
