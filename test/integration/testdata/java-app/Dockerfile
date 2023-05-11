FROM docker.io/eclipse-temurin:11-jdk as build

WORKDIR /src

COPY gradle ./gradle
COPY build.gradle settings.gradle gradlew ./
RUN ./gradlew --version

COPY . /src
RUN ./gradlew build --no-daemon

FROM docker.io/eclipse-temurin:11-jre

WORKDIR /app

COPY --from=build /src/build/libs/demo-0.0.1-SNAPSHOT.jar /app/demo.jar
ADD https://github.com/parca-dev/perf-map-agent/releases/download/v0.0.1/libperfmap.so /app/libperfmap.so

ENTRYPOINT ["java", "-XX:+PreserveFramePointer", "-agentpath:/app/libperfmap.so", "-jar", "/app/demo.jar"]
