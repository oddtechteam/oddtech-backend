package com.complaint.backend.dtos;

import java.util.Date;

import lombok.Data;

@Data
public class CommentDTO {
     private Long id;
    private String content;
    private Date createdAt;
    private Long postedUserId;
    // private String postName;
    private String postedName;
    private Long taskId;

}
