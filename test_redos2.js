const headersPart = "Subject: " + "a".repeat(100) + "\n \n \n \n \n \n \n \n \n \n" + " ".repeat(100000);
const start = Date.now();
const subjectMatch = headersPart.match(/^Subject:\s*([^\r\n]+(?:\r?\n[ \t]+[^\r\n]+)*)/mi);
console.log("Subject match took", Date.now() - start, "ms");
