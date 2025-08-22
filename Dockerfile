# ---- Build ----
FROM maven:3.9.8-eclipse-temurin-21 AS build
WORKDIR /app
COPY pom.xml .
RUN mvn -q -DskipTests dependency:go-offline
COPY src ./src
RUN mvn -q -DskipTests package

# ---- Run ----
FROM eclipse-temurin:21-jre
WORKDIR /app
# enable preview at runtime (you compile with --enable-preview)
ENV JAVA_OPTS="--enable-preview"
ENV SERVER_PORT=${PORT}
COPY --from=build /app/target/*.jar app.jar

# (Optional) write GCP creds from env into a file, then run the app
COPY <<'SH' /app/entrypoint.sh
#!/bin/sh
set -e
if [ -n "$GCP_CREDENTIALS_JSON" ]; then
  echo "$GCP_CREDENTIALS_JSON" > /app/gcp-sa.json
  export GOOGLE_APPLICATION_CREDENTIALS=/app/gcp-sa.json
  export SPRING_CLOUD_GCP_CREDENTIALS_LOCATION=file:/app/gcp-sa.json
fi
exec java $JAVA_OPTS -Dserver.port=${SERVER_PORT} -jar /app/app.jar
SH
RUN chmod +x /app/entrypoint.sh

EXPOSE 8080
ENTRYPOINT ["/app/entrypoint.sh"]
