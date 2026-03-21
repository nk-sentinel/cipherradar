plugins {
    java
    id("org.sonarqube") version "5.0.0.4638"
}

group = "com.cipherradar.sonarqube"
version = "0.1.0"

repositories {
    mavenCentral()
}

java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}

dependencies {
    // SonarQube Plugin API
    compileOnly("org.sonarsource.api.plugin:sonar-plugin-api:10.8.0.2315")

    // JSON parsing for SARIF / generic issue format
    implementation("com.google.code.gson:gson:2.11.0")

    // Testing
    testImplementation("junit:junit:4.13.2")
    testImplementation("org.assertj:assertj-core:3.26.0")
    testImplementation("org.sonarsource.api.plugin:sonar-plugin-api:10.8.0.2315")
}

tasks.jar {
    manifest {
        attributes(
            "Plugin-Key" to "cipherradar",
            "Plugin-Class" to "com.cipherradar.sonarqube.CipherRadarPlugin",
            "Plugin-Name" to "CipherRadar",
            "Plugin-Version" to project.version,
            "Plugin-Description" to "Cryptography Bill of Materials (CBOM) scanner — imports CipherRadar findings as external issues",
            "Plugin-Organization" to "nk-sentinel",
            "Plugin-Homepage" to "https://github.com/nk-sentinel/cipherradar",
            "Plugin-License" to "Apache-2.0",
            "Sonar-Version" to "10.4",
        )
    }

    // Fat JAR — bundle Gson
    from(configurations.runtimeClasspath.get().map { if (it.isDirectory) it else zipTree(it) })
    duplicatesStrategy = DuplicatesStrategy.EXCLUDE
}

tasks.test {
    useJUnit()
}
