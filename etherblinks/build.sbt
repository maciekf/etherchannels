name := """etherblinks"""

version := "0.1.0"

lazy val root = (project in file(".")).enablePlugins(PlayJava)

scalaVersion := "2.11.7"

libraryDependencies ++= Seq(
  javaJdbc,
  cache,
  javaWs,
  "io.swagger" % "swagger-annotations" % "1.5.8" % "compile",
  "com.netflix.feign" % "feign-core" % "8.16.0" % "compile"
)
