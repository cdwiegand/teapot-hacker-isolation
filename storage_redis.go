package teapot_hacker_isolation

import (
	"fmt"
	"strconv"
	"time"

	"github.com/go-redis/redis/v7"
)

type RedisStorage struct {
	config    *RedisStorageConfig
	redisConn *redis.Client
}

type RedisStorageConfig struct {
	Host string `json:"host"`
	Port int    `json:"port"`
}

func NewRedisStorageConfig() *RedisStorageConfig {
	return &RedisStorageConfig{
		Host: "localhost",
		Port: 6379,
	}
}

func NewRedisStorage(config *RedisStorageConfig) (*RedisStorage, error) {
	if config.Host == "" {
		config.Host = "localhost"
	}
	if config.Port == 0 {
		config.Port = 6379
	}
	client := redis.NewClient(&redis.Options{
		Addr: fmt.Sprintf("%s:%d", config.Host, config.Port),
	})

	return &RedisStorage{
		config:    config,
		redisConn: client,
	}, nil
}

func (r *RedisStorage) GetIpViolations(ip string) (int, error) {
	var foundI int
	found, err := r.redisConn.Get("ip:" + ip).Result()
	if err == nil {
		foundI, err = strconv.Atoi(found)
	}
	return foundI, err
}

func (r *RedisStorage) IncrIpViolations(ip string, jailTime time.Duration) (int, error) {
	newVal, err := r.redisConn.Incr("ip:" + ip).Result()
	if err == nil {
		r.redisConn.Expire("ip:"+ip, jailTime)
	}
	return int(newVal), err
}
