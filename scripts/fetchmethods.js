setTimeout(function(){
Java.perform(function(){
    console.log("Inside perform, fetching methods");

    var hook = Java.use("test.class.app.MainActivity");
    var ownMethods = hook.class.getDeclaredMethods();
    //console.log(ownMethods);
    send(ownMethods)


});

}, 0);