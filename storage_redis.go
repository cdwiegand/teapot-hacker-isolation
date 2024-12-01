package teapot_hacker_isolation

import (
	"fmt"
	"strconv"
	"time"

	"github.com/go-redis/redis/v7"
)

type RedisStorage struct {
	config    RedisStorageConfig
	redisConn *redis.Client
}

type RedisStorageConfig struct {
	Host string `json:"host"`
	Port int    `json:"port"`
}

func NewRedisStorage(config *Config) (*RedisStorage, error) {
	redisConfig := RedisStorageConfig{
		Host: config.RedisHost,
		Port: config.RedisPort,
	}
	if redisConfig.Host == "" {
		redisConfig.Host = "localhost"
	}
	if redisConfig.Port == 0 {
		redisConfig.Port = 6379
	}
	client := redis.NewClient(&redis.Options{
		Addr: fmt.Sprintf("%s:%d", redisConfig.Host, redisConfig.Port),
	})

	return &RedisStorage{
		config:    redisConfig,
		redisConn: client,
	}, nil
}

func (r *RedisStorage) GetIpViolations(ip string) StorageItem {
	var foundI int
	key := r.buildRedisKey(ip)
	found, err := r.redisConn.Get(key).Result()
	ret := StorageItem{}
	if err == nil {
		foundI, err = strconv.Atoi(found)
		if err == nil {
			ret.count = foundI
			t, _ := r.redisConn.TTL(key).Result()
			ret.expires = time.Now().Unix() + int64(t.Seconds())
		}
		r.redisConn.TTL(key)
	}
	return ret
}

func (r *RedisStorage) IncrIpViolations(ip string, jailTime time.Duration) StorageItem {
	ret := StorageItem{}
	key := r.buildRedisKey(ip)
	newVal, err := r.redisConn.Incr(key).Result()
	if err == nil {
		ret.count = int(newVal)
		ret.expires = time.Now().Unix() + int64(jailTime.Seconds())
		r.redisConn.ExpireAtUnix(key, ret.expires)
	}
	return ret
}

func (r *RedisStorage) buildRedisKey(ip string) string {
	return "ip:" + ip
}
