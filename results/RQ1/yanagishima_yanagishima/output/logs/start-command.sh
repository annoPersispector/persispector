cd application && /usr/lib/jvm/java-11-openjdk-amd64/bin/java -Xmx1G -cp "build/package/lib/*:/tmp/yjx/lib/*" yanagishima.YanagishimaApplication \
 --spring.config.location=src/main/resources/config/ \
 --server.port=18209 --server.address=127.0.0.1 \
 '--spring.datasource.url=jdbc:mysql://localhost:3306/test?socketFactory=org.newsclub.net.mysql.AFUNIXDatabaseSocketFactory&junixsocket.file=/tmp/ymysql/mysql.sock&useSSL=false&allowPublicKeyRetrieval=true' \
 --spring.jpa.show-sql=true --logging.level.org.hibernate.engine.jdbc.spi.SqlExceptionHelper=DEBUG
