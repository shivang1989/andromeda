setTimeout(function(){
Java.perform(function(){
    console.log("Inside perform");

    Java.enumerateLoadedClasses(
    {
        "onMatch": function(className){
         //console.log(className)
         send(className)
        },
        "onComplete":function(){
        send("Done")
        }
    }
    )

});

}, 0);
