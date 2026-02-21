@set path=C:\Program Files\Java\jdk1.8.0_181\bin;%path% 
@"java.exe" -cp "mqs.jar" "org.java8.MinimalQuicServer" 1>log.txt 2>&1

@pause 