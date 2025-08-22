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

# You compile with preview; enable it at runtime too (remove if not needed)
ENV JAVA_OPTS="--enable-preview"

# App JAR
COPY --from=build /app/target/*.jar /app/app.jar

# Optional: write GCP creds from env to a file at runtime
COPY <<'SH' /entrypoint.sh
#!/usr/bin/env sh
set -e
if [ -n "$GCP_CREDENTIALS_JSON" ]; then
  printf '%s' "$GCP_CREDENTIALS_JSON" > /app/gcp-sa.json
  export GOOGLE_APPLICATION_CREDENTIALS=/app/gcp-sa.json
  export SPRING_CLOUD_GCP_CREDENTIALS_LOCATION=file:/app/gcp-sa.json
fi
# Bind Spring to the Railway-provided PORT at runtime (no intermediate SERVER_PORT)
exec java $JAVA_OPTS -Dserver.port=${PORT} -jar /app/app.jar
SH
RUN chmod +x /entrypoint.sh

EXPOSE 8080
ENTRYPOINT ["/entrypoint.sh"]
