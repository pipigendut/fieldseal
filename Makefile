.PHONY: test test-go test-ruby vectors

test: test-go test-ruby

test-go:
	cd go && go test ./...

test-ruby:
	bundle exec ruby -Iruby/lib ruby/test/siv_test.rb
	bundle exec ruby -Iruby/lib ruby/test/pii_test.rb
	bundle exec ruby -Iruby/lib ruby/test/active_record_test.rb

vectors:
	cd go && UPDATE_VECTORS=1 go test ./pii -run TestUpdateVectors -count=1
