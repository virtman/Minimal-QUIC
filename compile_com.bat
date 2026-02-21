@rem taskkill /IM java.exe /T /F

@rem set path=C:\Program Files\Java\jdk11.0.5_10\bin;%path%
@rem set JAVA_HOME=C:\Program Files\Java\jdk11.0.5_10

@rem set path=C:\Program Files\Java\jdk1.6.0_45\bin;%path%
@rem set JAVA_HOME=C:\Program Files (x86)\Java\jdk1.6.0_45

@set path=C:\Program Files\Java\jdk1.8.0_181\bin;%path%
@set JAVA_HOME=C:\Program Files\Java\jdk1.8.0_181


@FOR %%F IN (*.class) DO del %%F>nul
@FOR %%F IN (*.~ava) DO del %%F>nul
@FOR %%F IN (*.jar) DO del %%F>nul
@FOR %%F IN (udp_log.txt) DO del %%F>nul
@FOR %%F IN (org\java8\*.class) DO del %%F>nul
@FOR %%F IN (org\java8\*.~ava) DO del %%F>nul

@FOR %%F IN (org\java8\MinimalQuicServer.java) DO "javac.exe" -Xlint:unchecked -cp "" %%F -O -deprecation -g 2>err.txt

@FOR %%F IN (org\java8\*.~ava) DO del %%F>nul
@FOR %%F IN (*.~ava) DO del %%F>nul

@rem jar.exe -cfvm my.jar MANIFEST.mf .\..\..\org\java77\*.class
@jar.exe -cfvm mqs.jar MANIFEST.mf org\java8\*.class

@FOR %%F IN (org\java8\*.class) DO del %%F>nul

@rem pause
@rem "C:\Program Files (x86)\Java\jdk1.6.0_45\bin\pack200.exe" -E9 -v -G -r mqs.jar 