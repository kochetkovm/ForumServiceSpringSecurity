package telran.java29.forum.controller;

import java.security.Principal;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import telran.java29.forum.dto.DatePeriodDto;
import telran.java29.forum.dto.NewCommentDto;
import telran.java29.forum.dto.NewPostDto;
import telran.java29.forum.dto.PostDto;
import telran.java29.forum.dto.PostUpdateDto;
import telran.java29.forum.service.ForumService;

@RestController
@RequestMapping("/forum")
public class ForumController {
	@Autowired
	ForumService service;

	@PostMapping("/post/{id}")
//	@PreAuthorize("#newPost.author == authentication.name and hasAnyRole('ADMIN', 'MODERATOR', 'USER')")
	public PostDto addPost(@RequestBody NewPostDto newPost, @PathVariable("id") String author) {
		return service.addNewPost(newPost, author);
	}

	@GetMapping("/post/{id}")
	public PostDto getPost(@PathVariable String id) {
		return service.getPost(id);
	}

	@DeleteMapping("/post/{id}")
	public PostDto removePost(@PathVariable String id) {
		return service.removePost(id);
	}

	@PutMapping("/post")
	public PostDto updatePost(@RequestBody PostUpdateDto postUpdateDto, Authentication authentication) {
		return service.updatePost(postUpdateDto, authentication.getName());
	}

	@PutMapping("/post/{id}/like")
	public boolean addLike(@PathVariable String id) {
		return service.addLike(id);
	}

	@PutMapping("/post/{id}/comment/{author}")
//	@PreAuthorize("#newCommentDto.user eq authentication.name and hasAnyRole('ADMIN', 'MODERATOR', 'USER')")
	public PostDto addComment(@PathVariable String id, @PathVariable String author, @RequestBody NewCommentDto newCommentDto) {
		return service.addComment(id, author, newCommentDto);
	}

	@PostMapping("/posts/tags")
	public Iterable<PostDto> getPostsByTags(@RequestBody List<String> tags) {
		return service.findPostsByTags(tags);
	}

	@GetMapping("/posts/author/{author}")
	public Iterable<PostDto> getPostsByAuthor(@PathVariable String author) {
		return service.findPostsByAuthor(author);
	}

	@PostMapping("/posts/period")
	public Iterable<PostDto> getPostsBetweenDate(@RequestBody DatePeriodDto periodDto) {
		return service.findPostsByDates(periodDto);
	}

}
