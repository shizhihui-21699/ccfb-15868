ThisBuild / scalaVersion := "3.3.4"
ThisBuild / organization := "shapelink"
ThisBuild / version := "0.1.0"

lazy val root = (project in file("."))
  .settings(
    name := "shapelink",
    Compile / mainClass := Some("shapelink.cli.Main"),
    libraryDependencies += "org.scalameta" %% "munit" % "1.0.2" % Test,
    Test / fork := true,
    run / fork := true,
    run / connectInput := false,
    scalacOptions ++= Seq("-deprecation", "-feature", "-unchecked"),
    Compile / doc / sources := Seq.empty
  )
